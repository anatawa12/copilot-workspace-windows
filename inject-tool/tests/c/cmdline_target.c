/*
 * cmdline_target.c — minimal no-CRT x86 Windows EXE that prints its own
 * command line.
 *
 * Used by the parameter-injection integration test to verify that stub.dll
 * correctly replaces "/UPDATE" / "/P" arguments in the process command line
 * before transferring control to the original entry point.
 *
 * NOTE: GetCommandLineW() on modern Windows returns a pointer cached at
 * process startup.  stub.dll patches ProcessParameters->CommandLine.Buffer
 * in the PEB, but if the new string is longer than the original (requiring a
 * new heap allocation) the cached pointer in GetCommandLineW still points to
 * the old buffer.  We therefore read the command line buffer DIRECTLY from the
 * PEB to observe whatever stub.dll wrote:
 *   FS:[0x30]              → PEB base address
 *   PEB  + 0x10            → ProcessParameters pointer
 *   ProcessParams + 0x44   → CommandLine.Buffer (WCHAR*)
 *
 * Build (MSVC x86, no CRT):
 *   cl /nologo /W3 /Ox /GS- /c cmdline_target.c
 *   link /NODEFAULTLIB /ENTRY:entry /SUBSYSTEM:CONSOLE /DYNAMICBASE:NO
 *        /OUT:cmdline_target.exe cmdline_target.obj kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/*
 * Force all functions that stub.dll imports to be present in this EXE's IAT.
 * inject-tool requires every DLL import to already exist in the target EXE.
 * A volatile pointer table prevents the linker from dead-stripping these refs.
 */
typedef void (*fnptr_t)(void);
volatile fnptr_t _required_imports[] = {
    (fnptr_t)GetStdHandle,
    (fnptr_t)WriteFile,
    (fnptr_t)ExitProcess,
    (fnptr_t)HeapAlloc,
    (fnptr_t)GetProcessHeap,
    (fnptr_t)WriteConsoleW,
};

/*
 * Read the command-line buffer directly from the PEB, bypassing
 * GetCommandLineW()'s startup-time cache.  This always reflects the current
 * ProcessParameters->CommandLine.Buffer, even after stub.dll has swapped in a
 * fresh heap allocation.
 */
static WCHAR* peb_cmdline_buffer(void)
{
    DWORD peb;
    DWORD pp;
    __asm {
        mov eax, dword ptr fs:[0x30]
        mov peb, eax
    }
    pp = *(DWORD *)(peb + 0x10);     /* PEB->ProcessParameters           */
    return *(WCHAR **)(pp + 0x44);   /* ProcessParameters->CommandLine.Buffer */
}

void __cdecl entry(void)
{
    DWORD written;
    WCHAR *wcmd;
    char buf[2048];
    int len;
    HANDLE h;

    wcmd = peb_cmdline_buffer();
    len = WideCharToMultiByte(CP_UTF8, 0, wcmd, -1, buf, (int)sizeof(buf), NULL, NULL);
    if (len > 0) len--; /* strip null terminator */

    h = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(h, buf, (DWORD)len, &written, NULL);
    WriteFile(h, "\n", 1, &written, NULL);
    ExitProcess(0);
}
