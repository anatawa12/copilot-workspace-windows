//! stub-dll — no_std / no_main x86 Windows DLL, injection stub.
//!
//! # Purpose
//! inject-tool embeds this DLL into a target EXE as a new `.patch` section and
//! redirects the EXE entry point to `DllMainCRTStartup`.  At runtime:
//!
//!   Windows loader resolves target.exe imports → jumps to DllMainCRTStartup
//!       → patches the command line if /UPDATE or /P is present
//!       → calls inner_entry (patched by inject-tool with original EXE entry VA)
//!           → original EXE entry point runs normally
//!
//! # Fixes vs. the reference sample
//! - `inner_entry` is now a `static mut` **function-pointer variable** exported
//!   as a DATA symbol.  inject-tool patches the 4-byte slot with the original
//!   EXE entry VA; at runtime `DllMainCRTStartup` calls through the pointer.
//!   (The original code defined it as a regular function, so overwriting its
//!   first 4 bytes with an address would corrupt the code and crash.)
//! - PEB access uses `fs:[0x30]` (x86 linear PEB address) instead of the
//!   incorrect `mov reg, fs` (which copies only the 16-bit segment selector).
//! - `MaximumLength` is in bytes; comparison now uses `cap * 2`.
//!
//! # Build
//! ```
//! RUSTFLAGS="-C link-arg=/ENTRY:DllMainCRTStartup" \
//!   cargo build --target i686-pc-windows-msvc
//! ```
//! (The `.cargo/config.toml` in this crate already sets the target and flags.)

#![no_std]
#![no_main]

extern crate windows_sys;

use core::ptr::null;
use windows_sys::w;
use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::System::Console::{GetStdHandle, WriteConsoleW, STD_ERROR_HANDLE};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HEAP_ZERO_MEMORY};
use windows_sys::Win32::System::Threading::ExitProcess;

// ─── wc! helper ──────────────────────────────────────────────────────────────

macro_rules! wc {
    ($value:literal) => {{
        #[allow(unused_unsafe)]
        unsafe {
            WCstr::from_cstr(w!($value))
        }
    }};
}

// ─── WCstr — null-terminated UTF-16 string wrapper ───────────────────────────

#[derive(Copy, Clone)]
struct WCstr(*const u16);

impl WCstr {
    const unsafe fn from_cstr(s: *const u16) -> WCstr {
        WCstr(s)
    }

    fn as_ptr(self) -> *const u16 {
        self.0
    }

    fn len(self) -> usize {
        unsafe { wcslen(self.as_ptr()) }
    }

    fn starts_with(self, s: WCstr) -> bool {
        unsafe {
            let mut i = 0;
            loop {
                if *s.as_ptr().add(i) == 0 {
                    return true;
                }
                if *self.as_ptr().add(i) != *s.as_ptr().add(i) {
                    return false;
                }
                i += 1;
            }
        }
    }

    fn contains(self, other: WCstr) -> bool {
        unsafe {
            let mut h = self.as_ptr();
            while *h != 0 {
                let mut p = h;
                let mut n = other.as_ptr();
                while *p != 0 && *n != 0 && *p == *n {
                    p = p.add(1);
                    n = n.add(1);
                }
                if *n == 0 {
                    return true;
                }
                h = h.add(1);
            }
            false
        }
    }

    fn slice(self, start: usize) -> WCstr {
        WCstr(unsafe { self.as_ptr().add(start) })
    }

    fn index(self, c: u16, offset: usize) -> Option<usize> {
        unsafe {
            let mut i = offset;
            loop {
                let ch = *self.as_ptr().add(i);
                if ch == 0 {
                    return None;
                }
                if ch == c {
                    return Some(i);
                }
                i += 1;
            }
        }
    }

    fn contents(self) -> &'static [u16] {
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.len()) }
    }
}

const unsafe fn wcslen(mut s: *const u16) -> usize {
    let mut len = 0;
    unsafe {
        while *s != 0 {
            len += 1;
            s = s.add(1);
        }
    }
    len
}

// ─── Module-list helpers ──────────────────────────────────────────────────────

/// Case-insensitive compare of a UTF-16 module base name (length in bytes)
/// against an ASCII lowercase reference string.
unsafe fn wname_eq_ascii(name: *const u16, name_bytes: u16, ascii: &[u8]) -> bool {
    let chars = (name_bytes / 2) as usize;
    if chars != ascii.len() {
        return false;
    }
    for i in 0..chars {
        let wc = *name.add(i);
        let lc = if wc >= b'A' as u16 && wc <= b'Z' as u16 {
            wc + 32
        } else {
            wc
        };
        if lc != ascii[i] as u16 {
            return false;
        }
    }
    true
}

/// Scan all writable, non-executable sections of the loaded PE image at `base`
/// for 4-byte-aligned values equal to `old_ptr as u32` and replace each with
/// `new_ptr as u32`.
///
/// Used to update the `GetCommandLineW` cache pointer stored inside
/// kernel32.dll / kernelbase.dll.  The false-positive risk is negligible: the
/// old command-line buffer is a process-specific heap address that is
/// effectively unique within the module's writable data.
unsafe fn scan_and_replace_ptr(base: *const u8, old_ptr: *const u16, new_ptr: *const u16) {
    // Verify MZ signature.
    if *(base as *const u16) != 0x5A4D {
        return;
    }
    let e_lfanew = *((base as usize + 0x3C) as *const u32) as usize;
    // Verify PE\0\0 signature.
    if *((base as usize + e_lfanew) as *const u32) != 0x0000_4550 {
        return;
    }

    // IMAGE_FILE_HEADER starts 4 bytes after the PE signature.
    let fh = e_lfanew + 4;
    let num_secs = *((base as usize + fh + 2) as *const u16) as usize;
    let size_of_opt = *((base as usize + fh + 16) as *const u16) as usize;
    // Section headers immediately follow the optional header.
    let shdrs = base as usize + fh + 20 + size_of_opt;

    // IMAGE_SECTION_HEADER field offsets:
    //   +0x08  Misc.VirtualSize
    //   +0x0C  VirtualAddress
    //   +0x24  Characteristics
    const SHDR: usize = 40;
    const SCN_WRITE: u32 = 0x8000_0000;
    const SCN_EXEC: u32 = 0x2000_0000;

    for i in 0..num_secs {
        let sh = shdrs + i * SHDR;
        let virt_size = *((sh + 8) as *const u32) as usize;
        let virt_addr = *((sh + 12) as *const u32) as usize;
        let characteristics = *((sh + 36) as *const u32);

        if characteristics & SCN_WRITE == 0 || characteristics & SCN_EXEC != 0 {
            continue;
        }

        let sec_start = base as usize + virt_addr;
        let sec_end = sec_start + virt_size;
        let mut addr = sec_start;
        while addr + 4 <= sec_end {
            if *(addr as *const u32) == old_ptr as u32 {
                *(addr as *mut u32) = new_ptr as u32;
            }
            addr += 4;
        }
    }
}

/// Walk the PEB InLoadOrder module list and call `scan_and_replace_ptr` on
/// every loaded module whose base name (case-insensitive) is "kernel32.dll"
/// or "kernelbase.dll".
///
/// `GetCommandLineW` caches the command-line buffer pointer during process
/// initialisation.  Patching PEB.ProcessParameters.CommandLine.Buffer alone is
/// insufficient when a new heap buffer is allocated; this function updates the
/// kernel-side cache so that `GetCommandLineW` returns the new buffer.
unsafe fn patch_kernel_cmdline_cache(old_ptr: *const u16, new_ptr: *const u16) {
    let peb: usize;
    core::arch::asm!(
        "mov {:e}, dword ptr fs:[0x30]",
        out(reg) peb,
        options(nostack, nomem, preserves_flags),
    );

    // PEB+0x0C → Ldr (*PEB_LDR_DATA)
    let ldr = *((peb + 0x0C) as *const usize);

    // PEB_LDR_DATA+0x0C → InLoadOrderModuleList (LIST_ENTRY)
    let list_head = ldr + 0x0C;
    let mut flink = *(list_head as *const usize);

    while flink != list_head {
        // LDR_DATA_TABLE_ENTRY offsets (x86 / 32-bit):
        //   +0x018  DllBase
        //   +0x02C  BaseDllName.Length  (u16, in bytes)
        //   +0x030  BaseDllName.Buffer  (*u16)
        let dll_base = *((flink + 0x18) as *const usize);
        let name_len = *((flink + 0x2C) as *const u16);
        let name_buf = *((flink + 0x30) as *const *const u16);

        if dll_base != 0
            && (wname_eq_ascii(name_buf, name_len, b"kernel32.dll")
                || wname_eq_ascii(name_buf, name_len, b"kernelbase.dll"))
        {
            scan_and_replace_ptr(dll_base as *const u8, old_ptr, new_ptr);
        }

        flink = *(flink as *const usize); // follow Flink
    }
}

// ─── Minimal PEB / process-parameters overlay (x86) ─────────────────────────
//
// We only map the fields we need:
//
//   PEB (x86):
//     +0x10  ProcessParameters  →  *RTL_USER_PROCESS_PARAMETERS
//
//   RTL_USER_PROCESS_PARAMETERS (x86):
//     +0x40  CommandLine        →  UNICODE_STRING
//               .Length           (u16, bytes)
//               .MaximumLength    (u16, bytes)
//               .Buffer           (*mut u16)

#[allow(dead_code)] // layout documentation only; accessed via raw pointer arithmetic
#[repr(C)]
struct Peb {
    _pad:                 [u8; 0x10],
    process_parameters:   *mut ProcessParams,
}

#[repr(C)]
struct ProcessParams {
    _pad:             [u8; 0x40],
    cmd_length:       u16,   // bytes used
    cmd_max_length:   u16,   // bytes allocated
    cmd_buffer:       *mut u16,
}

/// Returns a pointer to the process's RTL_USER_PROCESS_PARAMETERS.
///
/// Reads the PEB base from FS:[0x30] (x86 TEB self-pointer to PEB),
/// then dereferences PEB+0x10 for ProcessParameters.
#[inline(always)]
unsafe fn get_process_params() -> *mut ProcessParams {
    let peb: usize;
    // FS:[0x30] holds the linear address of the PEB on x86.
    core::arch::asm!(
        "mov {:e}, dword ptr fs:[0x30]",
        out(reg) peb,
        options(nostack, nomem, preserves_flags),
    );
    // PEB+0x10 = ProcessParameters pointer
    *((peb + 0x10) as *const *mut ProcessParams)
}

// ─── inner_entry — patched by inject-tool ────────────────────────────────────
//
// inject-tool locates this symbol in the DLL export table (DATA export) and
// overwrites the 4-byte slot with the original EXE AddressOfEntryPoint VA.
//
// DllMainCRTStartup calls through this pointer to hand off to the original
// EXE entry point after the command-line patch.

/// Stub default: returns FALSE before inject-tool has patched the pointer.
unsafe extern "C" fn inner_entry_default() -> BOOL {
    0
}

/// 4-byte function-pointer variable.  inject-tool writes the original EXE
/// entry VA here.  Must be a DATA export so the tool finds a writable slot,
/// not a code address.
#[no_mangle]
pub static mut inner_entry: unsafe extern "C" fn() -> BOOL = inner_entry_default;

// Tell the MSVC linker to export `inner_entry` as a DATA symbol.
#[used]
#[link_section = ".drectve"]
static EXPORT_DRECTVE: [u8; 25] = *b" /EXPORT:inner_entry,DATA";

// ─── DLL entry point ─────────────────────────────────────────────────────────

/// Raw DLL entry point — becomes the EXE entry point after injection.
///
/// Patches the process command line if `/UPDATE` or `/P` is present,
/// then calls `inner_entry` (which has been set to the original EXE entry).
///
/// Uses `extern "system"` (stdcall on x86) to match the standard DllMain ABI.
/// We never return — the original entry calls ExitProcess.
#[allow(non_snake_case)]
#[no_mangle]
unsafe extern "system" fn DllMainCRTStartup() -> BOOL {
    let pp = get_process_params();

    let old_cmd_buf = (*pp).cmd_buffer as *const u16;
    let command_line = WCstr::from_cstr(old_cmd_buf);

    // Locate where the parameters begin (after the executable path).
    let params_start = if command_line.starts_with(wc!("\"")) {
        // Quoted path: find the closing quote, then step past it.
        command_line.index('"' as u16, 1).map(|x| x + 1)
    } else {
        // Unquoted path: find the first space.
        command_line.index(' ' as u16, 1)
    }
    .unwrap_or(command_line.len());

    let cmd_params = command_line.slice(params_start);
    let should_replace =
        cmd_params.contains(wc!("/UPDATE")) || cmd_params.contains(wc!("/P"));

    if should_replace {
        let path_part = &command_line.contents()[..params_start];
        let update_params = wc!(" /SP- /SILENT /NOICONS /CURRENTUSER");
        let new_cap = params_start + update_params.len(); // characters (u16 units)

        // MaximumLength is in bytes; compare with new_cap * 2.
        if (new_cap * 2) < (*pp).cmd_max_length as usize {
            // Patch in-place.
            let area = core::slice::from_raw_parts_mut((*pp).cmd_buffer, new_cap);
            area[params_start..].copy_from_slice(update_params.contents());
            (*pp).cmd_length = (new_cap * 2) as u16;
        } else {
            // Allocate a fresh buffer.
            let heap = GetProcessHeap();
            let mem =
                HeapAlloc(heap, HEAP_ZERO_MEMORY, (new_cap + 1) * 2) as *mut u16;
            if !mem.is_null() {
                let area = core::slice::from_raw_parts_mut(mem, new_cap);
                area[..params_start].copy_from_slice(path_part);
                area[params_start..].copy_from_slice(update_params.contents());
                (*pp).cmd_length     = (new_cap * 2) as u16;
                (*pp).cmd_max_length = ((new_cap + 1) * 2) as u16;
                (*pp).cmd_buffer     = mem;
                // kernel32.dll / kernelbase.dll cache the command-line buffer
                // pointer set during process init.  Patching the PEB alone is
                // not enough; update the cached pointer so GetCommandLineW
                // returns the new buffer.
                patch_kernel_cmdline_cache(old_cmd_buf, mem as *const u16);
            }
        }
    }

    // Hand off to the original EXE entry point.
    inner_entry()
}

// ─── Panic handler ───────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    error_out(wc!("panic\n"));
    unsafe { ExitProcess(1) }
}

// ─── Diagnostics ─────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn error_out(msg: WCstr) {
    unsafe {
        let stderr = GetStdHandle(STD_ERROR_HANDLE);
        let mut written = 0u32;
        WriteConsoleW(stderr, msg.as_ptr() as *const core::ffi::c_void, msg.len() as u32, &mut written, null());
    }
}

// ─── CRT stubs ────────────────────────────────────────────────────────────────
//
// Provide every symbol that Rust's `libcore` (and the MSVC x86 ABI) requires
// so that the DLL does not import from `msvcrt.dll` or `vcruntime140.dll`.
// That keeps stub.dll's import table to kernel32.dll only, which guarantees
// inject-tool can satisfy every import from any target EXE that calls the same
// kernel32 functions.

#[no_mangle]
unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe { *dest.add(i) = *src.add(i) }
    }
    dest
}

#[no_mangle]
unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dest as usize) <= (src as usize) {
        for i in 0..n {
            unsafe { *dest.add(i) = *src.add(i) }
        }
    } else {
        for i in (0..n).rev() {
            unsafe { *dest.add(i) = *src.add(i) }
        }
    }
    dest
}

#[no_mangle]
unsafe extern "C" fn memset(dest: *mut u8, c: core::ffi::c_int, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe { *dest.add(i) = c as u8 }
    }
    dest
}

#[no_mangle]
unsafe extern "C" fn memcmp(
    a: *const u8,
    b: *const u8,
    n: usize,
) -> core::ffi::c_int {
    for i in 0..n {
        let diff =
            unsafe { (*a.add(i) as core::ffi::c_int) - (*b.add(i) as core::ffi::c_int) };
        if diff != 0 {
            return diff;
        }
    }
    0
}

/// C++ SEH frame handler.  `panic = "abort"` means we never actually unwind,
/// but the MSVC x86 ABI requires the symbol to be present.
#[no_mangle]
unsafe extern "C" fn __CxxFrameHandler3() {}

/// Floating-point usage marker required by the MSVC x86 ABI.
#[allow(non_upper_case_globals)]
#[no_mangle]
static _fltused: core::ffi::c_int = 1;

/// 64-bit unsigned divide/remainder helpers required by the MSVC x86 ABI.
///
/// LLVM generates calls to `__aulldiv` / `__aullrem` (exact symbol names,
/// no cdecl `_` prefix) for u64 operations on x86.  We provide them here
/// using only shifts and subtracts to avoid infinite recursion (using `/` or
/// `%` on u64 would itself call these helpers).
///
/// `#[export_name]` bypasses MSVC cdecl's leading-underscore decoration so
/// the linker sees exactly `__aulldiv` / `__aullrem`.
#[export_name = "__aulldiv"]
unsafe extern "C" fn aulldiv_impl(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    let mut n = a;
    let mut d = b;
    let mut bit: u64 = 1;
    while d < n && (d >> 63) == 0 {
        d <<= 1;
        bit <<= 1;
    }
    let mut q: u64 = 0;
    while bit != 0 {
        if n >= d {
            n -= d;
            q |= bit;
        }
        d >>= 1;
        bit >>= 1;
    }
    q
}

#[export_name = "__aullrem"]
unsafe extern "C" fn aullrem_impl(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    let mut n = a;
    let mut d = b;
    let mut bit: u64 = 1;
    while d < n && (d >> 63) == 0 {
        d <<= 1;
        bit <<= 1;
    }
    while bit != 0 {
        if n >= d {
            n -= d;
        }
        d >>= 1;
        bit >>= 1;
    }
    n
}
