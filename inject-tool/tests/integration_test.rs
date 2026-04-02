//! Integration test: compile target EXE + Rust stub DLL → inject → run → verify.
//!
//! Requires:
//!   - MSVC 2022 x86 build tools  (for compiling target.c)
//!   - i686-pc-windows-msvc Rust target  (for building stub-dll)

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Locate the compiled `inject-tool.exe` relative to the test binary.
///
/// Cargo places the test binary in `target/debug/deps/` and the tool binary
/// in `target/debug/`.
fn find_inject_tool() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let deps = exe.parent().expect("deps dir");
    let debug = deps.parent().unwrap_or(deps);
    for dir in &[debug, deps] {
        let p = dir.join("inject-tool.exe");
        if p.exists() {
            return p;
        }
    }
    panic!("inject-tool.exe not found (searched {:?})", debug);
}

/// Find `vcvarsall.bat` for MSVC 2022 (any edition).
fn find_vcvarsall() -> Option<PathBuf> {
    for edition in &["Enterprise", "Professional", "Community", "BuildTools"] {
        let p = PathBuf::from(format!(
            r"C:\Program Files\Microsoft Visual Studio\2022\{}\VC\Auxiliary\Build\vcvarsall.bat",
            edition
        ));
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Run a command in a MSVC x86 environment via a temporary batch file.
///
/// Writing the commands to a `.bat` file and executing it sidesteps
/// `cmd /c` quote-nesting problems with paths that contain spaces.
fn msvc_x86(vcvarsall: &Path, work_dir: &Path, cmd: &str) {
    // `call "vcvarsall.bat" x86`  sets up the x86 build environment.
    let bat = work_dir.join("_msvc_build.bat");
    let content = format!(
        "@echo off\r\ncall \"{}\" x86\r\nif errorlevel 1 exit /b 1\r\n{}\r\n",
        vcvarsall.display(),
        cmd,
    );
    fs::write(&bat, content).expect("write batch file");

    let out = Command::new("cmd")
        .args(["/c", bat.to_str().unwrap()])
        .current_dir(work_dir)
        .output()
        .expect("cmd /c bat");

    assert!(
        out.status.success(),
        "MSVC command failed:\nCMD: {}\nSTDOUT:\n{}\nSTDERR:\n{}",
        cmd,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Compile `tests/c/target.c` into `<work_dir>/target.exe` (no CRT, x86).
fn build_target_exe(vcvarsall: &Path, work_dir: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/c/target.c");
    fs::copy(&src, work_dir.join("target.c")).expect("copy target.c");
    msvc_x86(
        vcvarsall,
        work_dir,
        "cl /nologo /W3 /Ox /GS- /c target.c && \
         link /NODEFAULTLIB /ENTRY:entry /SUBSYSTEM:CONSOLE /DYNAMICBASE:NO \
              /OUT:target.exe target.obj kernel32.lib",
    );
    work_dir.join("target.exe")
}

/// Compile `tests/c/cmdline_target.c` into `<work_dir>/cmdline_target.exe` (no CRT, x86).
fn build_cmdline_target_exe(vcvarsall: &Path, work_dir: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/c/cmdline_target.c");
    fs::copy(&src, work_dir.join("cmdline_target.c")).expect("copy cmdline_target.c");
    msvc_x86(
        vcvarsall,
        work_dir,
        "cl /nologo /W3 /Ox /GS- /c cmdline_target.c && \
         link /NODEFAULTLIB /ENTRY:entry /SUBSYSTEM:CONSOLE /DYNAMICBASE:NO \
              /OUT:cmdline_target.exe cmdline_target.obj kernel32.lib",
    );
    work_dir.join("cmdline_target.exe")
}

/// Build `stub-dll` (Rust no_std, i686-pc-windows-msvc) and return the DLL path.
fn build_stub_dll() -> PathBuf {
    // CARGO_MANIFEST_DIR = inject-tool/  →  parent = workspace root
    let stub_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("stub-dll");

    let status = Command::new("cargo")
        .args(["build"])
        .current_dir(&stub_dir)
        .status()
        .expect("cargo build stub-dll");
    assert!(status.success(), "cargo build stub-dll failed");

    stub_dir.join("target/i686-pc-windows-msvc/debug/stub.dll")
}

// ─── test ────────────────────────────────────────────────────────────────────

/// Full injection pipeline:
///
/// 1. Compile `tests/c/target.c` → 32-bit no-CRT `target.exe`
/// 2. Build `stub-dll` → 32-bit no_std `stub.dll`
/// 3. Run `inject-tool target.exe stub.dll patched.exe`
/// 4. Run `patched.exe` and assert it produces the original EXE's output.
#[test]
fn test_injection_pipeline() {
    // Skip gracefully when MSVC build tools are absent.
    let vcvarsall = match find_vcvarsall() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: MSVC vcvarsall.bat not found");
            return;
        }
    };

    let work_dir = std::env::temp_dir().join("inject_tool_test");
    fs::create_dir_all(&work_dir).unwrap();

    let inject_tool = find_inject_tool();
    let target_exe  = build_target_exe(&vcvarsall, &work_dir);
    let stub_dll    = build_stub_dll();
    let patched_exe = work_dir.join("patched.exe");

    // ── inject ───────────────────────────────────────────────────────────────
    let inject_out = Command::new(&inject_tool)
        .args([&target_exe, &stub_dll, &patched_exe])
        .output()
        .expect("run inject-tool");

    assert!(
        inject_out.status.success(),
        "inject-tool failed:\nSTDOUT: {}\nSTDERR: {}",
        String::from_utf8_lossy(&inject_out.stdout),
        String::from_utf8_lossy(&inject_out.stderr),
    );

    // ── run patched.exe ───────────────────────────────────────────────────────
    let run = Command::new(&patched_exe)
        .output()
        .expect("run patched.exe");

    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);

    assert_eq!(
        run.status.code(),
        Some(0),
        "patched.exe non-zero exit\nstdout: {:?}\nstderr: {:?}",
        stdout,
        stderr,
    );
    assert_eq!(
        stdout.as_ref(),
        "original\n",
        "unexpected stdout from patched.exe: {:?}",
        stdout,
    );
}

/// Parameter-injection test:
///
/// 1. Compile `tests/c/cmdline_target.c` → 32-bit no-CRT `cmdline_target.exe`
///    (prints its own command line to stdout then exits).
/// 2. Build `stub-dll` → 32-bit no_std `stub.dll`.
/// 3. Run `inject-tool cmdline_target.exe stub.dll patched_cmdline.exe`.
/// 4. Run `patched_cmdline.exe /UPDATE` and assert that stub.dll replaced
///    the argument with ` /SP- /SILENT /NOICONS /CURRENTUSER`.
#[test]
fn test_parameter_injection() {
    // Skip gracefully when MSVC build tools are absent.
    let vcvarsall = match find_vcvarsall() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: MSVC vcvarsall.bat not found");
            return;
        }
    };

    let work_dir = std::env::temp_dir().join("inject_tool_test_cmdline");
    fs::create_dir_all(&work_dir).unwrap();

    let inject_tool       = find_inject_tool();
    let cmdline_target    = build_cmdline_target_exe(&vcvarsall, &work_dir);
    let stub_dll          = build_stub_dll();
    let patched_cmdline   = work_dir.join("patched_cmdline.exe");

    // ── inject ───────────────────────────────────────────────────────────────
    let inject_out = Command::new(&inject_tool)
        .args([&cmdline_target, &stub_dll, &patched_cmdline])
        .output()
        .expect("run inject-tool");

    assert!(
        inject_out.status.success(),
        "inject-tool failed:\nSTDOUT: {}\nSTDERR: {}",
        String::from_utf8_lossy(&inject_out.stdout),
        String::from_utf8_lossy(&inject_out.stderr),
    );

    // ── run with /UPDATE ─────────────────────────────────────────────────────
    // stub.dll replaces "/UPDATE" with " /SP- /SILENT /NOICONS /CURRENTUSER".
    let run = Command::new(&patched_cmdline)
        .arg("/UPDATE")
        .output()
        .expect("run patched_cmdline.exe");

    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);

    assert_eq!(
        run.status.code(),
        Some(0),
        "patched_cmdline.exe non-zero exit\nstdout: {:?}\nstderr: {:?}",
        stdout,
        stderr,
    );
    assert!(
        !stdout.contains("/UPDATE"),
        "command line still contains /UPDATE (not replaced): {:?}",
        stdout,
    );
    assert!(
        stdout.contains("/SP-"),
        "command line missing /SP- (replacement not applied): {:?}",
        stdout,
    );
}
