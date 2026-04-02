/*
 * target.c — minimal no-CRT x86 Windows EXE used as injection target.
 *
 * Imports: GetStdHandle, WriteFile, ExitProcess (kernel32)
 * Entry:   entry()  — prints "original\n" then exits with code 0.
 *
 * Build (MSVC x86, no CRT):
 *   cl /nologo /W3 /Ox /GS- /c target.c
 *   link /NODEFAULTLIB /ENTRY:entry /SUBSYSTEM:CONSOLE /OUT:target.exe
 *        target.obj kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const char msg[] = "original\n";

void __cdecl entry(void)
{
    DWORD written;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(h, msg, sizeof(msg) - 1, &written, NULL);
    ExitProcess(0);
}
