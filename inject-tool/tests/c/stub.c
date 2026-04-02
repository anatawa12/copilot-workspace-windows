/*
 * stub.c — no-CRT, no-std x86 Windows DLL used as the injection stub.
 *
 * Design
 * ------
 * inject-tool embeds this DLL into target.exe as a new .patch section and
 * redirects the EXE entry point here.  At runtime the sequence is:
 *
 *   Windows loader
 *     → resolves target.exe imports (kernel32 IAT filled with real addresses)
 *     → jumps to stub_entry   (new EXE entry point)
 *         → prints "stub\n"
 *         → jumps to inner_entry  (patched with original EXE entry VA)
 *             → original entry prints "original\n" and calls ExitProcess
 *
 * IAT redirect
 * ------------
 * inject-tool creates a 6-byte  "jmp dword ptr [exe_iat_va]"  thunk for every
 * function this DLL imports, and points the DLL's own IAT slot at that thunk.
 * At runtime: call [dll_iat] → call thunk → jmp [exe_iat] → real function.
 *
 * Symbol inner_entry
 * ------------------
 * Exported as a 4-byte void* variable initialised to NULL.
 * inject-tool patches it with the original EXE AddressOfEntryPoint VA before
 * writing the patched executable.
 *
 * Requirements
 * ------------
 * - No CRT   (/NODEFAULTLIB /ENTRY:stub_entry)
 * - No TLS, no delay imports
 * - All imports (GetStdHandle, WriteFile) must already exist in target.exe
 *
 * Build (MSVC x86, no CRT):
 *   cl /nologo /W3 /Ox /GS- /c stub.c
 *   link /NODEFAULTLIB /DLL /ENTRY:stub_entry /OUT:stub.dll
 *        stub.obj kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Patched by inject-tool with the original EXE entry point VA. */
__declspec(dllexport) void *inner_entry;

static const char stub_msg[] = "stub\n";

/* Raw entry point — becomes the EXE entry after injection.
   Called by the OS with no arguments (EXE entry convention). */
void __cdecl stub_entry(void)
{
    DWORD written;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(h, stub_msg, sizeof(stub_msg) - 1, &written, NULL);

    /* Jump to the original EXE entry point. */
    ((void (__cdecl *)(void))inner_entry)();
}
