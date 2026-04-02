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

// ─── binary helpers ──────────────────────────────────────────────────────────

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

// ─── PE structures ───────────────────────────────────────────────────────────

struct Pe {
    /// File offset of NT signature ("PE\0\0").
    nt: usize,
    /// File offset of IMAGE_FILE_HEADER (nt + 4).
    fh: usize,
    /// File offset of IMAGE_OPTIONAL_HEADER32 (nt + 24).
    oh: usize,
    oh_size: u16,

    image_base: u32,
    entry_rva: u32,
    sec_align: u32,
    file_align: u32,
    size_of_image: u32,
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
    /// File offset of the 40-byte section header entry.
    hdr_off: usize,
}

impl Sec {
    fn end_rva(&self) -> u32 {
        self.virtual_address + self.virtual_size.max(self.raw_size)
    }
}

impl Pe {
    fn parse(d: &[u8]) -> Result<Self, String> {
        if d.len() < 0x40 {
            return Err("file too small".into());
        }
        if r16(d, 0) != 0x5A4D {
            return Err("not a DOS executable (bad MZ signature)".into());
        }
        let nt = r32(d, 0x3C) as usize;
        if nt + 4 > d.len() {
            return Err("e_lfanew points beyond file".into());
        }
        if r32(d, nt) != 0x0000_4550 {
            return Err("invalid PE signature".into());
        }

        let fh = nt + 4; // IMAGE_FILE_HEADER
        if fh + 20 > d.len() {
            return Err("file header out of bounds".into());
        }
        let machine = r16(d, fh);
        if machine != 0x014C {
            return Err(format!("not x86 (machine=0x{:04X})", machine));
        }

        let num_secs = r16(d, fh + 2) as usize;
        let oh_size = r16(d, fh + 16);
        let oh = fh + 20; // IMAGE_OPTIONAL_HEADER32

        if oh + oh_size as usize > d.len() {
            return Err("optional header out of bounds".into());
        }
        let magic = r16(d, oh);
        if magic != 0x010B {
            return Err(format!("not PE32 (magic=0x{:04X})", magic));
        }

        let entry_rva = r32(d, oh + 16);
        let image_base = r32(d, oh + 28);
        let sec_align = r32(d, oh + 32);
        let file_align = r32(d, oh + 36);
        let size_of_image = r32(d, oh + 56);
        let size_of_headers = r32(d, oh + 60);

        let shdrs_base = oh + oh_size as usize;
        let mut sections = Vec::with_capacity(num_secs);
        for i in 0..num_secs {
            let o = shdrs_base + i * 40;
            if o + 40 > d.len() {
                return Err(format!("section header {} out of bounds", i));
            }
            let mut name = [0u8; 8];
            name.copy_from_slice(&d[o..o + 8]);
            sections.push(Sec {
                name,
                virtual_size: r32(d, o + 8),
                virtual_address: r32(d, o + 12),
                raw_size: r32(d, o + 16),
                raw_ptr: r32(d, o + 20),
                characteristics: r32(d, o + 36),
                hdr_off: o,
            });
        }

        Ok(Pe {
            nt,
            fh,
            oh,
            oh_size,
            image_base,
            entry_rva,
            sec_align,
            file_align,
            size_of_image,
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

    /// File offset of DataDirectory entry `idx` (each entry is 8 bytes: RVA + Size).
    fn ddir(&self, idx: usize) -> usize {
        self.oh + 96 + idx * 8
    }

    /// File offset of the section headers region.
    fn shdrs_base(&self) -> usize {
        self.oh + self.oh_size as usize
    }
}

// ─── EXE: collect imports  (dll_lower, func_name) → IAT RVA ─────────────────

fn read_exe_imports(d: &[u8], pe: &Pe) -> Result<HashMap<(String, String), u32>, String> {
    let mut map = HashMap::new();
    let dir = pe.ddir(1); // IMAGE_DIRECTORY_ENTRY_IMPORT
    let rva = r32(d, dir);
    let sz = r32(d, dir + 4);
    if rva == 0 || sz == 0 {
        return Ok(map);
    }

    let mut desc = pe
        .rva2off(rva)
        .ok_or("import directory RVA not mapped to any section")?;

    loop {
        if desc + 20 > d.len() {
            break;
        }
        let orig = r32(d, desc);
        let name_rva = r32(d, desc + 12);
        let iat_rva = r32(d, desc + 16);

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
            .ok_or("INT/IAT RVA not mapped in EXE imports")?;
        let mut cur_iat = iat_rva;

        loop {
            if int_off + 4 > d.len() {
                break;
            }
            let thunk = r32(d, int_off);
            if thunk == 0 {
                break;
            }
            if thunk & 0x8000_0000 == 0 {
                // Import by name: thunk is RVA of IMAGE_IMPORT_BY_NAME
                let ibn = pe
                    .rva2off(thunk)
                    .ok_or("import-by-name RVA not mapped")?;
                let func = read_cstr(d, ibn + 2); // skip 2-byte Hint
                map.insert((dll_lo.clone(), func), cur_iat);
            }
            int_off += 4;
            cur_iat += 4;
        }

        desc += 20;
    }

    Ok(map)
}

// ─── DLL: collect imports  Vec<(dll_lower, func_name, iat_rva_in_dll)> ───────

fn read_dll_imports(d: &[u8], pe: &Pe) -> Result<Vec<(String, String, u32)>, String> {
    let mut entries = Vec::new();
    let dir = pe.ddir(1);
    let rva = r32(d, dir);
    let sz = r32(d, dir + 4);
    if rva == 0 || sz == 0 {
        return Ok(entries);
    }

    let mut desc = pe
        .rva2off(rva)
        .ok_or("DLL import directory RVA not mapped")?;

    loop {
        if desc + 20 > d.len() {
            break;
        }
        let orig = r32(d, desc);
        let name_rva = r32(d, desc + 12);
        let iat_rva = r32(d, desc + 16);

        if name_rva == 0 && orig == 0 && iat_rva == 0 {
            break;
        }
        if name_rva == 0 {
            break;
        }

        let dll_off = pe
            .rva2off(name_rva)
            .ok_or("DLL import DLL-name RVA not mapped")?;
        let dll_lo = read_cstr(d, dll_off).to_lowercase();

        let int_rva = if orig != 0 { orig } else { iat_rva };
        let mut int_off = pe
            .rva2off(int_rva)
            .ok_or("DLL INT/IAT RVA not mapped")?;
        let mut cur_iat = iat_rva;

        loop {
            if int_off + 4 > d.len() {
                break;
            }
            let thunk = r32(d, int_off);
            if thunk == 0 {
                break;
            }
            if thunk & 0x8000_0000 == 0 {
                let ibn = pe
                    .rva2off(thunk)
                    .ok_or("DLL import-by-name RVA not mapped")?;
                let func = read_cstr(d, ibn + 2);
                entries.push((dll_lo.clone(), func, cur_iat));
            }
            int_off += 4;
            cur_iat += 4;
        }

        desc += 20;
    }

    Ok(entries)
}

// ─── DLL: find a symbol RVA ──────────────────────────────────────────────────

/// Look up `target` in the DLL's export directory.  Returns the symbol's RVA.
fn find_export(d: &[u8], pe: &Pe, target: &str) -> Option<u32> {
    let dir = pe.ddir(0); // IMAGE_DIRECTORY_ENTRY_EXPORT
    let rva = r32(d, dir);
    let sz = r32(d, dir + 4);
    if rva == 0 || sz == 0 {
        return None;
    }

    let exp = pe.rva2off(rva)?;
    if exp + 40 > d.len() {
        return None;
    }

    let num_names = r32(d, exp + 24) as usize;
    let funcs_rva = r32(d, exp + 28);
    let names_rva = r32(d, exp + 32);
    let ords_rva = r32(d, exp + 36);

    let funcs_off = pe.rva2off(funcs_rva)?;
    let names_off = pe.rva2off(names_rva)?;
    let ords_off = pe.rva2off(ords_rva)?;

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

/// Look up `target` (or `_target`) in the COFF symbol table.  Returns the RVA.
fn find_coff_symbol(d: &[u8], pe: &Pe, target: &str) -> Option<u32> {
    let sym_ptr = r32(d, pe.fh + 8) as usize; // PointerToSymbolTable
    let num_sym = r32(d, pe.fh + 12) as usize; // NumberOfSymbols
    if sym_ptr == 0 || num_sym == 0 {
        return None;
    }
    if sym_ptr.checked_add(num_sym.checked_mul(18)?)? > d.len() {
        return None;
    }

    let strtab = sym_ptr + num_sym * 18;
    let decorated = format!("_{}", target);
    let mut i = 0usize;

    while i < num_sym {
        let o = sym_ptr + i * 18;
        if o + 18 > d.len() {
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

// ─── core injection ──────────────────────────────────────────────────────────

fn inject(exe_data: &[u8], dll_data: &[u8]) -> Result<Vec<u8>, String> {
    // ── Parse headers ──────────────────────────────────────────────────────
    let exe_pe = Pe::parse(exe_data).map_err(|e| format!("EXE: {}", e))?;
    let dll_pe = Pe::parse(dll_data).map_err(|e| format!("DLL: {}", e))?;

    let original_entry_rva = exe_pe.entry_rva;
    let dll_image_base = dll_pe.image_base;
    let dll_entry_rva = dll_pe.entry_rva;
    let dll_img_size = dll_pe.size_of_image as usize;

    // ── Collect imports ────────────────────────────────────────────────────
    let exe_imports = read_exe_imports(exe_data, &exe_pe)
        .map_err(|e| format!("reading EXE imports: {}", e))?;
    let dll_imports = read_dll_imports(dll_data, &dll_pe)
        .map_err(|e| format!("reading DLL imports: {}", e))?;

    // ── Validate: every DLL import must exist in the EXE ──────────────────
    for (dll_name, func_name, _iat_rva) in &dll_imports {
        if !exe_imports.contains_key(&(dll_name.clone(), func_name.clone())) {
            return Err(format!(
                "DLL requires {}!{} which is not imported by the EXE",
                dll_name, func_name
            ));
        }
    }

    // ── Find inner_entry ───────────────────────────────────────────────────
    let inner_entry_rva = find_inner_entry(dll_data, &dll_pe)?;

    // ── Build the DLL in-memory image ──────────────────────────────────────
    let mut dll_image = vec![0u8; dll_img_size];

    // Copy PE headers
    let hdr_len = (dll_pe.size_of_headers as usize).min(dll_data.len()).min(dll_img_size);
    dll_image[..hdr_len].copy_from_slice(&dll_data[..hdr_len]);

    // Copy each section into its virtual address slot
    for sec in &dll_pe.sections {
        if sec.raw_size == 0 {
            continue;
        }
        let src_start = sec.raw_ptr as usize;
        let copy_len = sec.raw_size as usize;
        let dst_start = sec.virtual_address as usize;

        if src_start + copy_len > dll_data.len() {
            return Err(format!(
                "DLL section '{}' raw data (0x{:X}+0x{:X}) exceeds file size",
                std::str::from_utf8(&sec.name).unwrap_or("?"),
                src_start,
                copy_len
            ));
        }
        if dst_start + copy_len > dll_img_size {
            return Err(format!(
                "DLL section '{}' virtual range exceeds SizeOfImage",
                std::str::from_utf8(&sec.name).unwrap_or("?")
            ));
        }
        dll_image[dst_start..dst_start + copy_len]
            .copy_from_slice(&dll_data[src_start..src_start + copy_len]);
    }

    // ── Compute new section placement in EXE ───────────────────────────────
    let last = exe_pe
        .sections
        .last()
        .ok_or("EXE has no sections")?;

    let new_rva = align_up(last.end_rva(), exe_pe.sec_align);
    let new_raw = align_up(last.raw_ptr + last.raw_size, exe_pe.file_align);

    // ── Apply DLL base relocations ─────────────────────────────────────────
    // The DLL will reside at virtual address: exe_image_base + new_rva
    let load_base = exe_pe.image_base.wrapping_add(new_rva);
    let delta = (load_base as i64) - (dll_image_base as i64);

    {
        let dir = dll_pe.ddir(5); // IMAGE_DIRECTORY_ENTRY_BASERELOC
        let reloc_rva = r32(dll_data, dir);
        let reloc_sz = r32(dll_data, dir + 4);

        if reloc_rva != 0 && reloc_sz != 0 {
            let reloc_start = dll_pe
                .rva2off(reloc_rva)
                .ok_or("DLL relocation directory RVA not mapped")?;
            let reloc_end = reloc_start + reloc_sz as usize;

            let mut pos = reloc_start;
            while pos + 8 <= reloc_end.min(dll_data.len()) {
                let block_rva = r32(dll_data, pos);
                let block_size = r32(dll_data, pos + 4);
                if block_size < 8 {
                    break;
                }
                let num_entries = (block_size - 8) / 2;
                for j in 0..num_entries as usize {
                    let eo = pos + 8 + j * 2;
                    if eo + 2 > dll_data.len() {
                        break;
                    }
                    let entry = r16(dll_data, eo);
                    let rel_type = entry >> 12;
                    let offset = (entry & 0x0FFF) as u32;

                    if rel_type == 3 {
                        // IMAGE_REL_BASED_HIGHLOW
                        let target_rva = block_rva + offset;
                        let idx = target_rva as usize;
                        if idx + 4 > dll_image.len() {
                            return Err(format!(
                                "relocation target RVA 0x{:08X} out of DLL image",
                                target_rva
                            ));
                        }
                        let old = u32::from_le_bytes(
                            dll_image[idx..idx + 4].try_into().unwrap(),
                        );
                        let new_val = (old as i64 + delta) as u32;
                        dll_image[idx..idx + 4].copy_from_slice(&new_val.to_le_bytes());
                    }
                }
                pos += block_size as usize;
            }
        }
    }

    // ── Redirect DLL IAT entries via JMP thunks ────────────────────────────
    //
    // The DLL's code does  `call dword ptr [dll_iat_slot]`  (single-indirect).
    // That slot must hold a *callable* address.  We cannot store the EXE's IAT
    // data VA directly there because the IAT is filled with function pointers by
    // the loader and executing those bytes as code would crash.
    //
    // Instead, for each import we write a 6-byte JMP thunk in the .patch section
    // immediately after the DLL image:
    //
    //   FF 25 [exe_iat_va]   →   jmp dword ptr [exe_iat_va]
    //
    // Then point the DLL's IAT slot at the thunk VA.  At runtime:
    //   call [dll_iat_slot]  →  call thunk  →  jmp [exe_iat_va]
    //                                         →  jumps to the real function
    //
    // The thunk area is appended after the DLL image within the .patch section.
    let thunk_base_rva = new_rva + dll_img_size as u32;

    let mut thunk_data: Vec<u8> = Vec::with_capacity(dll_imports.len() * 6);

    for (i, (dll_name, func_name, dll_iat_rva)) in dll_imports.iter().enumerate() {
        let exe_iat_rva = exe_imports[&(dll_name.clone(), func_name.clone())];
        let exe_iat_va = exe_pe.image_base.wrapping_add(exe_iat_rva);

        // VA of the thunk for this import
        let thunk_va = exe_pe
            .image_base
            .wrapping_add(thunk_base_rva)
            .wrapping_add((i * 6) as u32);

        // Point DLL's IAT slot at the thunk
        let idx = *dll_iat_rva as usize;
        if idx + 4 > dll_image.len() {
            return Err(format!(
                "DLL IAT entry RVA 0x{:08X} out of DLL image",
                dll_iat_rva
            ));
        }
        dll_image[idx..idx + 4].copy_from_slice(&thunk_va.to_le_bytes());

        // Write the 6-byte JMP thunk: FF 25 [exe_iat_va LE]
        thunk_data.push(0xFF);
        thunk_data.push(0x25);
        thunk_data.extend_from_slice(&exe_iat_va.to_le_bytes());
    }

    // ── Disable the embedded DLL's import directory ────────────────────────
    // Zero out DataDirectory[1] in the in-memory DLL header so that if any
    // tool walks the PE structures of the patched EXE it won't try to load the
    // embedded DLL's imports as part of the outer image.
    let imp_dir_off = dll_pe.oh + 104; // oh + 96 + 1*8
    if imp_dir_off + 8 <= dll_image.len() {
        dll_image[imp_dir_off..imp_dir_off + 8].fill(0);
    }

    // ── Patch inner_entry with the original EXE entry VA ──────────────────
    let orig_entry_va = exe_pe.image_base.wrapping_add(original_entry_rva);
    let idx = inner_entry_rva as usize;
    if idx + 4 > dll_image.len() {
        return Err(format!(
            "inner_entry RVA 0x{:08X} out of DLL image",
            inner_entry_rva
        ));
    }
    dll_image[idx..idx + 4].copy_from_slice(&orig_entry_va.to_le_bytes());

    // ── Verify space for new section header ────────────────────────────────
    let new_sh_off = exe_pe.shdrs_base() + exe_pe.sections.len() * 40;
    if new_sh_off + 40 > exe_pe.size_of_headers as usize {
        return Err(format!(
            "no room for new section header: end of new header would be at 0x{:X}, \
             but SizeOfHeaders = 0x{:X}",
            new_sh_off + 40,
            exe_pe.size_of_headers
        ));
    }

    // ── Build the output file ──────────────────────────────────────────────
    let patch_content_size = dll_img_size + thunk_data.len();
    let raw_size_aligned = align_up(patch_content_size as u32, exe_pe.file_align);
    let required_len = new_raw as usize + raw_size_aligned as usize;
    let mut out = exe_data.to_vec();
    if required_len > out.len() {
        out.resize(required_len, 0);
    }

    // Write DLL memory image into the new section's raw data area
    out[new_raw as usize..new_raw as usize + dll_img_size].copy_from_slice(&dll_image);
    // Write JMP thunks immediately after the DLL image
    if !thunk_data.is_empty() {
        let thunk_off = new_raw as usize + dll_img_size;
        out[thunk_off..thunk_off + thunk_data.len()].copy_from_slice(&thunk_data);
    }

    // ── Update EXE headers ─────────────────────────────────────────────────

    // New entry point: DLL entry offset within the new section
    w32(&mut out, exe_pe.oh + 16, new_rva + dll_entry_rva);

    // New SizeOfImage
    let new_size_of_image = align_up(new_rva + patch_content_size as u32, exe_pe.sec_align);
    w32(&mut out, exe_pe.oh + 56, new_size_of_image);

    // Increment NumberOfSections
    let old_num = r16(&out, exe_pe.fh + 2);
    w16(&mut out, exe_pe.fh + 2, old_num + 1);

    // Append new section header (.patch)
    const SEC_CODE: u32 = 0x0000_0020; // IMAGE_SCN_CNT_CODE
    const SEC_EXEC: u32 = 0x2000_0000; // IMAGE_SCN_MEM_EXECUTE
    const SEC_READ: u32 = 0x4000_0000; // IMAGE_SCN_MEM_READ

    out[new_sh_off..new_sh_off + 8].copy_from_slice(b".patch\0\0");
    w32(&mut out, new_sh_off + 8, patch_content_size as u32); // VirtualSize
    w32(&mut out, new_sh_off + 12, new_rva); // VirtualAddress
    w32(&mut out, new_sh_off + 16, raw_size_aligned); // SizeOfRawData
    w32(&mut out, new_sh_off + 20, new_raw); // PointerToRawData
    w32(&mut out, new_sh_off + 24, 0); // PointerToRelocations
    w32(&mut out, new_sh_off + 28, 0); // PointerToLinenumbers
    w16(&mut out, new_sh_off + 32, 0); // NumberOfRelocations
    w16(&mut out, new_sh_off + 34, 0); // NumberOfLinenumbers
    w32(&mut out, new_sh_off + 36, SEC_CODE | SEC_EXEC | SEC_READ); // Characteristics

    Ok(out)
}

// ─── tests ───────────────────────────────────────────────────────────────────

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
