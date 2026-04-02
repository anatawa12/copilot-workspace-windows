//! inject-tool
//!
//! Injects a 32-bit stub DLL into a 32-bit Windows EXE by:
//!   1. Embedding the DLL image as a new `.patch` section.
//!   2. Redirecting the EXE entry point to the DLL entry.
//!   3. Satisfying DLL imports from the EXE's existing IAT.
//!   4. Patching the DLL's `inner_entry` variable with the original EXE entry VA.
//!
//! Usage: inject-tool <target.exe> <stub.dll> <output.exe>

use std::collections::HashMap;
use std::mem::{offset_of, size_of};

// PE structs and constants from the windows-sys crate, so field offsets are
// derived from the canonical Windows SDK layout rather than hardcoded numbers.
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER32, IMAGE_SECTION_HEADER,
    IMAGE_NT_OPTIONAL_HDR32_MAGIC,
};
use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_I386;
use windows_sys::Win32::System::SystemServices::{
    IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, IMAGE_REL_BASED_HIGHLOW,
};

/// DataDirectory index constants.
const DDIR_EXPORT: usize = 0;
const DDIR_IMPORT: usize = 1;
const DDIR_BASERELOC: usize = 5;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <target.exe> <stub.dll> <output.exe>", args[0]);
        std::process::exit(1);
    }

    let exe_data = std::fs::read(&args[1])
        .unwrap_or_else(|e| fatal(&format!("cannot read '{}': {}", args[1], e)));
    let dll_data = std::fs::read(&args[2])
        .unwrap_or_else(|e| fatal(&format!("cannot read '{}': {}", args[2], e)));

    let output = inject(&exe_data, &dll_data)
        .unwrap_or_else(|e| fatal(&format!("injection failed: {}", e)));

    std::fs::write(&args[3], &output)
        .unwrap_or_else(|e| fatal(&format!("cannot write '{}': {}", args[3], e)));

    println!("wrote patched executable to '{}'", args[3]);
}

fn fatal(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}

//  Binary helpers ─

/// Read a `T` from `d[o..]` without assuming alignment.
///
/// Using `read_unaligned` is correct here because PE data inside a `Vec<u8>`
/// is not guaranteed to be aligned to `align_of::<T>()`.
fn read_at<T: Copy>(d: &[u8], o: usize) -> Result<T, String> {
    let sz = size_of::<T>();
    if o.checked_add(sz).map_or(true, |end| end > d.len()) {
        return Err(format!(
            "reading {} bytes at 0x{:X}: out of bounds (data len 0x{:X})",
            sz, o, d.len()
        ));
    }
    Ok(unsafe { (d.as_ptr().add(o) as *const T).read_unaligned() })
}

fn r16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}

fn r32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

fn w16(d: &mut [u8], o: usize, v: u16) {
    d[o..o + 2].copy_from_slice(&v.to_le_bytes());
}

fn w32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn align_up(v: u32, a: u32) -> u32 {
    if a <= 1 {
        return v;
    }
    (v + a - 1) & !(a - 1)
}

/// Read a null-terminated ASCII/UTF-8 string from `d[o..]`.
fn read_cstr(d: &[u8], o: usize) -> String {
    let end = d[o..].iter().position(|&b| b == 0).unwrap_or(d.len() - o);
    String::from_utf8_lossy(&d[o..o + end]).into_owned()
}

//  PE structures ─

struct Pe {
    /// File offset of IMAGE_FILE_HEADER.
    fh: usize,
    /// File offset of IMAGE_OPTIONAL_HEADER32.
    oh: usize,
    /// Value of IMAGE_FILE_HEADER.SizeOfOptionalHeader.
    oh_size: u16,

    image_base: u32,
    entry_rva: u32,
    sec_align: u32,
    file_align: u32,
    size_of_headers: u32,

    sections: Vec<Sec>,
}

struct Sec {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,
}

impl Sec {
    fn end_rva(&self) -> u32 {
        self.virtual_address + self.virtual_size.max(self.raw_size)
    }
}

impl Pe {
    fn parse(d: &[u8]) -> Result<Self, String> {
        //  DOS header 
        let dos: IMAGE_DOS_HEADER =
            read_at(d, 0).map_err(|e| format!("DOS header: {}", e))?;
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(format!(
                "not a DOS executable (e_magic=0x{:04X})",
                dos.e_magic
            ));
        }

        let nt = dos.e_lfanew as usize;
        let sig: u32 = read_at(d, nt).map_err(|e| format!("PE signature: {}", e))?;
        if sig != IMAGE_NT_SIGNATURE {
            return Err(format!("invalid PE signature (0x{:08X})", sig));
        }

        //  File header 
        let fh = nt + size_of::<u32>(); // skip 4-byte Signature
        let fh_s: IMAGE_FILE_HEADER =
            read_at(d, fh).map_err(|e| format!("file header: {}", e))?;
        if fh_s.Machine != IMAGE_FILE_MACHINE_I386 {
            return Err(format!("not x86 (machine=0x{:04X})", fh_s.Machine));
        }

        let num_secs = fh_s.NumberOfSections as usize;
        let oh_size = fh_s.SizeOfOptionalHeader;

        //  Optional header 
        let oh = fh + size_of::<IMAGE_FILE_HEADER>();
        if oh + oh_size as usize > d.len() {
            return Err("optional header out of bounds".into());
        }
        let oh_s: IMAGE_OPTIONAL_HEADER32 =
            read_at(d, oh).map_err(|e| format!("optional header: {}", e))?;
        if oh_s.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
            return Err(format!("not PE32 (magic=0x{:04X})", oh_s.Magic));
        }

        let entry_rva = oh_s.AddressOfEntryPoint;
        let image_base = oh_s.ImageBase;
        let sec_align = oh_s.SectionAlignment;
        let file_align = oh_s.FileAlignment;
        let size_of_headers = oh_s.SizeOfHeaders;

        //  Section headers 
        let shdrs_base = oh + oh_size as usize;
        let mut sections = Vec::with_capacity(num_secs);
        for i in 0..num_secs {
            let o = shdrs_base + i * size_of::<IMAGE_SECTION_HEADER>();
            let sec: IMAGE_SECTION_HEADER =
                read_at(d, o).map_err(|_| format!("section header {} out of bounds", i))?;
            sections.push(Sec {
                name: sec.Name,
                virtual_size: unsafe { sec.Misc.VirtualSize },
                virtual_address: sec.VirtualAddress,
                raw_size: sec.SizeOfRawData,
                raw_ptr: sec.PointerToRawData,
                characteristics: sec.Characteristics,
            });
        }

        Ok(Pe {
            fh,
            oh,
            oh_size,
            image_base,
            entry_rva,
            sec_align,
            file_align,
            size_of_headers,
            sections,
        })
    }

    /// Convert an RVA to a file offset using the section table.
    fn rva2off(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            let sz = s.virtual_size.max(s.raw_size);
            if rva >= s.virtual_address && rva < s.virtual_address + sz {
                return Some((s.raw_ptr + (rva - s.virtual_address)) as usize);
            }
        }
        None
    }

    /// File offset of DataDirectory entry `idx`.
    ///
    /// Uses `offset_of!(IMAGE_OPTIONAL_HEADER32, DataDirectory)` so the offset
    /// is derived from the windows-sys struct layout rather than a literal constant.
    fn ddir(&self, idx: usize) -> usize {
        self.oh
            + offset_of!(IMAGE_OPTIONAL_HEADER32, DataDirectory)
            + idx * size_of::<IMAGE_DATA_DIRECTORY>()
    }

    /// File offset of the section-headers region.
    fn shdrs_base(&self) -> usize {
        self.oh + self.oh_size as usize
    }
}

//  Import-table reader ─

/// Read all name-based imports from the PE image `d`/`pe` and return them as
/// a flat list of `(dll_name_lowercase, function_name, iat_rva)` triples.
///
/// Returns an error if any import thunk uses ordinal-only form (high bit set),
/// as ordinal imports cannot be matched by name in the EXE's IAT.
fn read_imports(d: &[u8], pe: &Pe) -> Result<Vec<(String, String, u32)>, String> {
    let mut entries = Vec::new();
    let dir = pe.ddir(DDIR_IMPORT);
    let rva = r32(d, dir);
    let sz = r32(d, dir + 4);
    if rva == 0 || sz == 0 {
        return Ok(entries);
    }

    let mut desc_off = pe
        .rva2off(rva)
        .ok_or("import directory RVA not mapped to any section")?;

    loop {
        if desc_off + size_of::<IMAGE_IMPORT_DESCRIPTOR>() > d.len() {
            break;
        }
        let desc: IMAGE_IMPORT_DESCRIPTOR = read_at(d, desc_off)?;
        let orig = unsafe { desc.Anonymous.OriginalFirstThunk };
        let name_rva = desc.Name;
        let iat_rva = desc.FirstThunk;

        if name_rva == 0 && orig == 0 && iat_rva == 0 {
            break; // null terminator descriptor
        }
        if name_rva == 0 {
            break;
        }

        let dll_off = pe
            .rva2off(name_rva)
            .ok_or("import DLL name RVA not mapped")?;
        let dll_lo = read_cstr(d, dll_off).to_lowercase();

        let int_rva = if orig != 0 { orig } else { iat_rva };
        let mut int_off = pe
            .rva2off(int_rva)
            .ok_or("INT/IAT RVA not mapped in imports")?;
        let mut cur_iat = iat_rva;

        loop {
            if int_off + 4 > d.len() {
                break;
            }
            let thunk = r32(d, int_off);
            if thunk == 0 {
                break;
            }
            if thunk & 0x8000_0000 != 0 {
                return Err(format!(
                    "ordinal import not supported: {}!#{} (ordinal-only imports cannot \
                     be matched by name)",
                    dll_lo,
                    thunk & 0x7fff_ffff
                ));
            }
            // Import by name: thunk is RVA of IMAGE_IMPORT_BY_NAME
            let ibn = pe.rva2off(thunk).ok_or("import-by-name RVA not mapped")?;
            let func = read_cstr(d, ibn + 2); // skip 2-byte Hint
            entries.push((dll_lo.clone(), func, cur_iat));
            int_off += 4;
            cur_iat += 4;
        }

        desc_off += size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }

    Ok(entries)
}

//  DLL: find a symbol RVA 

/// Look up `target` in the DLL's export directory. Returns the symbol RVA.
fn find_export(d: &[u8], pe: &Pe, target: &str) -> Option<u32> {
    let dir = pe.ddir(DDIR_EXPORT);
    let rva = r32(d, dir);
    let sz = r32(d, dir + 4);
    if rva == 0 || sz == 0 {
        return None;
    }

    let exp_off = pe.rva2off(rva)?;
    let exp: IMAGE_EXPORT_DIRECTORY = read_at(d, exp_off).ok()?;

    let num_names = exp.NumberOfNames as usize;
    let funcs_off = pe.rva2off(exp.AddressOfFunctions)?;
    let names_off = pe.rva2off(exp.AddressOfNames)?;
    let ords_off = pe.rva2off(exp.AddressOfNameOrdinals)?;

    for i in 0..num_names {
        if names_off + i * 4 + 4 > d.len() {
            break;
        }
        let name_rva = r32(d, names_off + i * 4);
        let name_off = pe.rva2off(name_rva)?;
        let name = read_cstr(d, name_off);
        if name == target {
            if ords_off + i * 2 + 2 > d.len() {
                return None;
            }
            let ordinal = r16(d, ords_off + i * 2) as usize;
            if funcs_off + ordinal * 4 + 4 > d.len() {
                return None;
            }
            return Some(r32(d, funcs_off + ordinal * 4));
        }
    }
    None
}

/// Look up `target` (or `_target`) in the COFF symbol table. Returns the RVA.
///
/// COFF symbol entries are 18 bytes each; the IMAGE_FILE_HEADER fields
/// PointerToSymbolTable / NumberOfSymbols are accessed via offset_of! to avoid
/// hardcoded offsets.
fn find_coff_symbol(d: &[u8], pe: &Pe, target: &str) -> Option<u32> {
    let sym_ptr =
        r32(d, pe.fh + offset_of!(IMAGE_FILE_HEADER, PointerToSymbolTable)) as usize;
    let num_sym = r32(d, pe.fh + offset_of!(IMAGE_FILE_HEADER, NumberOfSymbols)) as usize;
    if sym_ptr == 0 || num_sym == 0 {
        return None;
    }

    const COFF_SYM_SIZE: usize = 18; // sizeof(IMAGE_SYMBOL)
    if sym_ptr.checked_add(num_sym.checked_mul(COFF_SYM_SIZE)?)? > d.len() {
        return None;
    }

    let strtab = sym_ptr + num_sym * COFF_SYM_SIZE;
    let decorated = format!("_{}", target);
    let mut i = 0usize;

    while i < num_sym {
        let o = sym_ptr + i * COFF_SYM_SIZE;
        if o + COFF_SYM_SIZE > d.len() {
            break;
        }

        let first4 = r32(d, o);
        let sym_name = if first4 == 0 {
            let str_off = r32(d, o + 4) as usize;
            if strtab + str_off < d.len() {
                read_cstr(d, strtab + str_off)
            } else {
                String::new()
            }
        } else {
            let nb = &d[o..o + 8];
            let end = nb.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&nb[..end]).into_owned()
        };

        let value = r32(d, o + 8);
        let section_num = i16::from_le_bytes([d[o + 12], d[o + 13]]);
        let aux_count = d[o + 17] as usize;

        if (sym_name == target || sym_name == decorated) && section_num > 0 {
            let sec_idx = (section_num as usize).wrapping_sub(1);
            if sec_idx < pe.sections.len() {
                return Some(pe.sections[sec_idx].virtual_address + value);
            }
        }

        i += 1 + aux_count;
    }

    None
}

/// Find the RVA of `inner_entry` in the DLL (export table first, then COFF).
fn find_inner_entry(d: &[u8], pe: &Pe) -> Result<u32, String> {
    find_export(d, pe, "inner_entry")
        .or_else(|| find_export(d, pe, "_inner_entry"))
        .or_else(|| find_coff_symbol(d, pe, "inner_entry"))
        .ok_or_else(|| "symbol 'inner_entry' not found in DLL (export table or COFF)".to_string())
}

//  core injection 

fn inject(exe_data: &[u8], dll_data: &[u8]) -> Result<Vec<u8>, String> {
    //  Parse headers 
    let exe_pe = Pe::parse(exe_data).map_err(|e| format!("EXE: {}", e))?;
    let dll_pe = Pe::parse(dll_data).map_err(|e| format!("DLL: {}", e))?;

    let original_entry_rva = exe_pe.entry_rva;
    let dll_image_base = dll_pe.image_base;
    let dll_entry_rva = dll_pe.entry_rva;

    //  Collect imports
    let exe_imports: HashMap<(String, String), u32> =
        read_imports(exe_data, &exe_pe)
            .map_err(|e| format!("reading EXE imports: {}", e))?
            .into_iter()
            .map(|(dll, func, iat_rva)| ((dll, func), iat_rva))
            .collect();
    let dll_imports = read_imports(dll_data, &dll_pe)
        .map_err(|e| format!("reading DLL imports: {}", e))?;

    //  Validate: every DLL import must exist in the EXE
    for (dll_name, func_name, _iat_rva) in &dll_imports {
        if !exe_imports.contains_key(&(dll_name.clone(), func_name.clone())) {
            return Err(format!(
                "DLL requires {}!{} which is not imported by the EXE",
                dll_name, func_name
            ));
        }
    }

    //  Find inner_entry
    let inner_entry_rva = find_inner_entry(dll_data, &dll_pe)?;

    //  Build embedded-section list ─
    //
    // Each non-.reloc DLL section becomes a separate EXE section placed at
    //   VirtualAddress = new_rva + dll_sec.virtual_address
    // so the original DLL inter-section gaps are preserved in virtual space.
    //
    // The Windows PE loader requires sections to be virtually contiguous —
    // a section whose VirtualAddress is not immediately adjacent to the
    // section-aligned end of the preceding section causes the loader to reject
    // the image with STATUS_INVALID_IMAGE_FORMAT (ERROR_BAD_EXE_FORMAT).
    // See: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    //      #section-table-section-headers (ordering / virtual-address rules)
    //
    // To satisfy this without adding blank section headers, we extend the
    // VirtualSize of an existing section to cover any gap:
    //   • Gap before the first DLL section → extend the last EXE section.
    //   • Gap between two DLL sections    → extend the preceding DLL section.
    //
    // The .reloc section is excluded — its data is consumed below and is not
    // needed at run time.

    //  Compute new section placement in EXE ─
    let last = exe_pe.sections.last().ok_or("EXE has no sections")?;
    let new_rva = align_up(last.end_rva(), exe_pe.sec_align);
    let new_raw = align_up(last.raw_ptr + last.raw_size, exe_pe.file_align);

    struct EmbedEntry {
        name: [u8; 8],
        virt_addr: u32,        // VirtualAddress in the output EXE
        virt_size: u32,        // VirtualSize in the section header
        characteristics: u32,
        buf: Vec<u8>,          // raw data; empty for BSS/uninitialised sections
        dll_sec_idx: usize,    // index into dll_pe.sections
    }

    let mut entries: Vec<EmbedEntry> = Vec::new();
    // cur_dll_va tracks the section-aligned virtual end of the last processed
    // DLL section (in DLL VA space, relative to DLL image base; starts at 0).
    let mut cur_dll_va: u32 = 0;
    // VA gap that must be covered by extending the last EXE section's
    // VirtualSize (set when the first DLL section doesn't start at VA 0).
    let mut extend_last_exe_vsize_by: u32 = 0;

    for (i, s) in dll_pe.sections.iter().enumerate() {
        let name_end = s.name.iter().position(|&b| b == 0).unwrap_or(s.name.len());
        if &s.name[..name_end] == b".reloc" {
            continue;
        }

        // If there is a virtual gap before this section, absorb it by
        // extending the preceding section's VirtualSize.
        if s.virtual_address > cur_dll_va {
            let gap = s.virtual_address - cur_dll_va;
            if entries.is_empty() {
                // Gap before the first DLL section: extend the last EXE section.
                extend_last_exe_vsize_by = gap;
            } else {
                // Gap between DLL sections: extend the preceding entry.
                entries.last_mut().unwrap().virt_size += gap;
            }
        }

        // Load raw bytes; pad to virtual extent for any zero-fill within the section.
        let vsize = s.virtual_size.max(s.raw_size);
        let buf = if s.raw_size > 0 {
            let src = s.raw_ptr as usize;
            let copy = (s.raw_size as usize).min(vsize as usize);
            if src + copy > dll_data.len() {
                return Err(format!(
                    "DLL section '{}' raw data (0x{:X}+0x{:X}) exceeds file size",
                    std::str::from_utf8(&s.name).unwrap_or("?"),
                    src,
                    s.raw_size
                ));
            }
            let mut b = vec![0u8; vsize as usize];
            b[..copy].copy_from_slice(&dll_data[src..src + copy]);
            b
        } else {
            // BSS section: no raw data in file, loader zero-initialises from VirtualSize.
            Vec::new()
        };

        entries.push(EmbedEntry {
            name: s.name,
            virt_addr: new_rva + s.virtual_address,
            virt_size: vsize,
            characteristics: s.characteristics,
            buf,
            dll_sec_idx: i,
        });

        // Advance the expected-VA pointer: section-aligned end of this section.
        cur_dll_va = align_up(s.virtual_address + vsize, exe_pe.sec_align);
    }

    //  Apply DLL base relocations and redirect IAT references 
    // All DLL sections reside at exe_image_base + new_rva + dll_sec.virtual_address.
    // The relocation delta is uniform across all sections.
    let load_base = exe_pe.image_base.wrapping_add(new_rva);
    let delta = (load_base as i64) - (dll_image_base as i64);

    // Build a map: dll_iat_va -> exe_iat_va for every import.
    //
    // In the DLL on-disk image, code that calls an imported function via IAT
    // uses an absolute VA operand equal to `dll_image_base + dll_iat_rva`.
    // The linker records every such location in the .reloc section as an
    // IMAGE_REL_BASED_HIGHLOW entry.  We detect these entries during the
    // relocation pass and replace the absolute address directly with the
    // corresponding EXE IAT VA (exe_image_base + exe_iat_rva), eliminating
    // the need for any appended JMP thunks.
    let iat_redirect: HashMap<u32, u32> = dll_imports
        .iter()
        .map(|(dll_name, func_name, dll_iat_rva)| {
            let exe_iat_rva = exe_imports[&(dll_name.clone(), func_name.clone())];
            let dll_iat_va = dll_image_base.wrapping_add(*dll_iat_rva);
            let exe_iat_va = exe_pe.image_base.wrapping_add(exe_iat_rva);
            (dll_iat_va, exe_iat_va)
        })
        .collect();

    {
        let dir = dll_pe.ddir(DDIR_BASERELOC);
        let reloc_rva = r32(dll_data, dir);
        let reloc_sz = r32(dll_data, dir + 4);

        if reloc_rva != 0 && reloc_sz != 0 {
            let reloc_start = dll_pe
                .rva2off(reloc_rva)
                .ok_or("DLL relocation directory RVA not mapped")?;
            let reloc_end = reloc_start + reloc_sz as usize;
            let blk_hdr_sz = size_of::<IMAGE_BASE_RELOCATION>();

            let mut pos = reloc_start;
            while pos + blk_hdr_sz <= reloc_end.min(dll_data.len()) {
                let blk: IMAGE_BASE_RELOCATION = read_at(dll_data, pos)
                    .map_err(|e| format!("relocation block: {}", e))?;
                if blk.SizeOfBlock < blk_hdr_sz as u32 {
                    break;
                }
                let num_entries = (blk.SizeOfBlock as usize - blk_hdr_sz) / 2;
                for j in 0..num_entries {
                    let eo = pos + blk_hdr_sz + j * 2;
                    if eo + 2 > dll_data.len() {
                        break;
                    }
                    let entry = r16(dll_data, eo);
                    let rel_type = (entry >> 12) as u32;
                    let offset = (entry & 0x0FFF) as u32;

                    if rel_type == IMAGE_REL_BASED_HIGHLOW {
                        let target_rva = blk.VirtualAddress + offset;
                        // Find which real section buffer contains this RVA.
                        // Relocations targeting skipped sections (e.g. .reloc self-
                        // references) are harmless to ignore.
                        let found = entries.iter_mut().find_map(|e| {
                            let s = &dll_pe.sections[e.dll_sec_idx];
                            let va = s.virtual_address;
                            let len = s.virtual_size.max(s.raw_size) as usize;
                            if target_rva >= va && (target_rva - va) as usize + 4 <= len {
                                Some((&mut e.buf, (target_rva - va) as usize))
                            } else {
                                None
                            }
                        });
                        if let Some((buf, off)) = found {
                            let old = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
                            // If this absolute address references a DLL IAT slot,
                            // replace it with the corresponding EXE IAT VA.
                            // Otherwise apply the standard load-time delta.
                            let new_val = if let Some(&exe_iat_va) = iat_redirect.get(&old) {
                                exe_iat_va
                            } else {
                                (old as i64 + delta) as u32
                            };
                            buf[off..off + 4].copy_from_slice(&new_val.to_le_bytes());
                        }
                    }
                }
                pos += blk.SizeOfBlock as usize;
            }
        }
    }

    //  Patch inner_entry with the original EXE entry VA 
    let orig_entry_va = exe_pe.image_base.wrapping_add(original_entry_rva);
    let found_entry = entries.iter_mut().find_map(|e| {
        let s = &dll_pe.sections[e.dll_sec_idx];
        let va = s.virtual_address;
        let len = s.virtual_size.max(s.raw_size) as usize;
        if inner_entry_rva >= va && (inner_entry_rva - va) as usize + 4 <= len {
            Some((&mut e.buf, (inner_entry_rva - va) as usize))
        } else {
            None
        }
    });
    match found_entry {
        Some((buf, off)) => buf[off..off + 4].copy_from_slice(&orig_entry_va.to_le_bytes()),
        None => return Err(format!(
            "inner_entry RVA 0x{:08X} not found in any embedded section",
            inner_entry_rva
        )),
    }

    //  Verify space for new section headers 
    let num_new_secs = entries.len();
    let sec_hdr_sz = size_of::<IMAGE_SECTION_HEADER>();
    let new_sh_off = exe_pe.shdrs_base() + exe_pe.sections.len() * sec_hdr_sz;
    if new_sh_off + num_new_secs * sec_hdr_sz > exe_pe.size_of_headers as usize {
        return Err(format!(
            "no room for {} new section headers: need 0x{:X} bytes but SizeOfHeaders = 0x{:X}",
            num_new_secs,
            new_sh_off + num_new_secs * sec_hdr_sz,
            exe_pe.size_of_headers
        ));
    }

    //  Compute file placements for each embedded section 
    // VirtualAddress = new_rva + dll_sec.virtual_address (preserves inter-section gaps).
    // PointerToRawData is packed consecutively in the file (no gap bytes on disk).
    // Sections with no raw data (BSS/filler) use SizeOfRawData = 0 and PointerToRawData = 0.
    let mut sec_placements: Vec<(u32, u32)> = Vec::new(); // (raw_ptr, raw_size_aligned)
    let mut cur_raw = new_raw;
    for entry in &entries {
        let (raw_ptr, raw_size_aligned) = if entry.buf.is_empty() {
            (0u32, 0u32)
        } else {
            let aligned = align_up(entry.buf.len() as u32, exe_pe.file_align);
            let ptr = cur_raw;
            cur_raw += aligned;
            (ptr, aligned)
        };
        sec_placements.push((raw_ptr, raw_size_aligned));
    }

    //  Build the output file 
    let mut out = exe_data.to_vec();
    if cur_raw as usize > out.len() {
        out.resize(cur_raw as usize, 0);
    }

    // Write each section's raw data into the output file.
    for (entry, &(raw_ptr, _)) in entries.iter().zip(sec_placements.iter()) {
        if !entry.buf.is_empty() {
            let start = raw_ptr as usize;
            out[start..start + entry.buf.len()].copy_from_slice(&entry.buf);
        }
    }

    //  Update EXE headers 

    // If the first DLL section doesn't start at VA 0 in the DLL image,
    // extend the last EXE section's VirtualSize to cover the gap between
    // the end of the EXE sections and the start of the first DLL section.
    if extend_last_exe_vsize_by > 0 {
        let last_sec_idx = exe_pe.sections.len() - 1;
        let sh_off = exe_pe.shdrs_base() + last_sec_idx * sec_hdr_sz;
        let last_sec = &exe_pe.sections[last_sec_idx];
        // New VirtualSize covers [last_sec.virtual_address, new_rva + extend).
        let new_vsize = new_rva + extend_last_exe_vsize_by - last_sec.virtual_address;
        w32(&mut out, sh_off + offset_of!(IMAGE_SECTION_HEADER, Misc), new_vsize);
    }

    // New entry point: DLL entry within the new section region.
    w32(
        &mut out,
        exe_pe.oh + offset_of!(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint),
        new_rva + dll_entry_rva,
    );

    // New SizeOfImage: virtual end of the last new section.
    let new_size_of_image = entries
        .iter()
        .map(|e| e.virt_addr + e.virt_size)
        .max()
        .map(|end| align_up(end, exe_pe.sec_align))
        .unwrap_or(new_rva + exe_pe.sec_align);
    w32(
        &mut out,
        exe_pe.oh + offset_of!(IMAGE_OPTIONAL_HEADER32, SizeOfImage),
        new_size_of_image,
    );

    // Increment NumberOfSections.
    let old_num = r16(&out, exe_pe.fh + offset_of!(IMAGE_FILE_HEADER, NumberOfSections));
    w16(
        &mut out,
        exe_pe.fh + offset_of!(IMAGE_FILE_HEADER, NumberOfSections),
        old_num + num_new_secs as u16,
    );

    // Write one section header per embedded entry.
    for (i, (entry, &(raw_ptr, raw_size_aligned))) in
        entries.iter().zip(sec_placements.iter()).enumerate()
    {
        let sh_off = new_sh_off + i * sec_hdr_sz;
        out[sh_off..sh_off + 8].copy_from_slice(&entry.name);
        w32(&mut out, sh_off + offset_of!(IMAGE_SECTION_HEADER, Misc), entry.virt_size);
        w32(&mut out, sh_off + offset_of!(IMAGE_SECTION_HEADER, VirtualAddress), entry.virt_addr);
        w32(&mut out, sh_off + offset_of!(IMAGE_SECTION_HEADER, SizeOfRawData), raw_size_aligned);
        w32(&mut out, sh_off + offset_of!(IMAGE_SECTION_HEADER, PointerToRawData), raw_ptr);
        w32(&mut out, sh_off + offset_of!(IMAGE_SECTION_HEADER, PointerToRelocations), 0);
        w32(&mut out, sh_off + offset_of!(IMAGE_SECTION_HEADER, PointerToLinenumbers), 0);
        w16(&mut out, sh_off + offset_of!(IMAGE_SECTION_HEADER, NumberOfRelocations), 0);
        w16(&mut out, sh_off + offset_of!(IMAGE_SECTION_HEADER, NumberOfLinenumbers), 0);
        w32(
            &mut out,
            sh_off + offset_of!(IMAGE_SECTION_HEADER, Characteristics),
            entry.characteristics,
        );
    }


    Ok(out)
}

//  tests 

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
        assert_eq!(align_up(512, 512), 512);
        assert_eq!(align_up(513, 512), 1024);
    }

    #[test]
    fn test_read_cstr() {
        let buf = b"hello\x00world";
        assert_eq!(read_cstr(buf, 0), "hello");
        assert_eq!(read_cstr(buf, 6), "world");
    }

    #[test]
    fn test_parse_bad_magic() {
        let data = vec![0u8; 512];
        assert!(Pe::parse(&data).is_err());
    }

    #[test]
    fn test_inject_bad_exe() {
        let result = inject(b"notanexe", b"notadll");
        assert!(result.is_err());
    }
}