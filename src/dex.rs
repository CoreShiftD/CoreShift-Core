// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal ZIP + DEX parser for reading TRANSACTION_* static int field values
//! from `framework.jar` without any subprocess or external tool.
//!
//! Only handles STORED (uncompressed) DEX entries. Android framework JARs
//! store DEX uncompressed so ART can mmap directly from the ZIP.

// ── Byte readers ──────────────────────────────────────────────────────────────

fn u16le(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn uleb128(b: &[u8], off: &mut usize) -> Option<u32> {
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*off)?;
        *off += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 { return Some(result); }
        shift += 7;
        if shift >= 35 { return None; }
    }
}

// ── ZIP ───────────────────────────────────────────────────────────────────────

const ZIP_EOCD_SIG:   [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const ZIP_CD_SIG:     [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const ZIP_LOCAL_SIG:  [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const ZIP_STORED: u16 = 0;

struct ZipEntry {
    local_off:  usize,
    comp_size:  usize,
    fname_hash: u64, // djb2 of filename
}

fn djb2(s: &[u8]) -> u64 {
    let mut h = 5381u64;
    for &b in s { h = h.wrapping_mul(33).wrapping_add(b as u64); }
    h
}

fn zip_find_dex_entries(data: &[u8]) -> Vec<ZipEntry> {
    // Scan backwards for EOCD (ignore ZIP comment — Android JARs have none).
    let scan_start = data.len().saturating_sub(65558);
    let eocd_pos = match data[scan_start..]
        .windows(4)
        .rposition(|w| w == ZIP_EOCD_SIG)
    {
        Some(p) => scan_start + p,
        None    => return Vec::new(),
    };

    let cd_size = match u32le(data, eocd_pos + 12) { Some(v) => v as usize, None => return Vec::new() };
    let cd_off  = match u32le(data, eocd_pos + 16) { Some(v) => v as usize, None => return Vec::new() };

    let mut pos = cd_off;
    let cd_end  = cd_off.saturating_add(cd_size);
    let mut entries = Vec::new();

    while pos + 46 <= cd_end && pos + 46 <= data.len() {
        if data.get(pos..pos + 4) != Some(&ZIP_CD_SIG) { break; }

        let compression = match u16le(data, pos + 10) { Some(v) => v, None => break };
        let comp_size   = match u32le(data, pos + 20) { Some(v) => v as usize, None => break };
        let local_off   = match u32le(data, pos + 42) { Some(v) => v as usize, None => break };
        let fname_len   = match u16le(data, pos + 28) { Some(v) => v as usize, None => break };
        let extra_len   = match u16le(data, pos + 30) { Some(v) => v as usize, None => break };
        let comment_len = match u16le(data, pos + 32) { Some(v) => v as usize, None => break };

        let fname_end = pos + 46 + fname_len;
        if fname_end > data.len() { break; }
        let fname = &data[pos + 46..fname_end];

        // Collect classes*.dex entries that are STORED.
        let is_dex = fname.starts_with(b"classes") && fname.ends_with(b".dex");
        if is_dex && compression == ZIP_STORED {
            entries.push(ZipEntry {
                local_off,
                comp_size,
                fname_hash: djb2(fname),
            });
        }

        pos = match pos.checked_add(46 + fname_len + extra_len + comment_len) {
            Some(v) => v,
            None    => break,
        };
    }

    // Sort classes.dex first (djb2 of b"classes.dex" < b"classes2.dex" etc. by content — just sort by hash to be deterministic; classes.dex is shortest so sort by fname_hash ascending mimics alphabetical).
    // Actually sort by comp_size descending: largest DEX is most likely to contain IActivityManager.
    entries.sort_by(|a, b| b.comp_size.cmp(&a.comp_size));
    entries
}

fn zip_entry_data<'a>(data: &'a [u8], entry: &ZipEntry) -> Option<&'a [u8]> {
    let lh = entry.local_off;
    if data.get(lh..lh + 4) != Some(&ZIP_LOCAL_SIG) { return None; }
    let fname_len = u16le(data, lh + 26)? as usize;
    let extra_len = u16le(data, lh + 28)? as usize;
    let data_start = lh + 30 + fname_len + extra_len;
    data.get(data_start..data_start + entry.comp_size)
}

// ── DEX ───────────────────────────────────────────────────────────────────────

const DEX_MAGIC: &[u8] = b"dex\n";

fn dex_string<'a>(dex: &'a [u8], string_ids_off: usize, idx: usize) -> Option<&'a [u8]> {
    let str_data_off = u32le(dex, string_ids_off + idx * 4)? as usize;
    // Skip ULEB128 UTF-16 length
    let mut off = str_data_off;
    loop {
        let b = *dex.get(off)?;
        off += 1;
        if b & 0x80 == 0 { break; }
    }
    // Null-terminated MUTF-8 bytes
    let start = off;
    while *dex.get(off)? != 0 { off += 1; }
    dex.get(start..off)
}

fn skip_encoded_value(dex: &[u8], off: &mut usize) -> Option<()> {
    let vbyte = *dex.get(*off)?;
    *off += 1;
    let vtype = vbyte & 0x1f;
    let varg  = (vbyte >> 5) as usize;
    match vtype {
        // value_arg+1 bytes follow
        0x00 | 0x02 | 0x03 | 0x04 | 0x06 |
        0x10 | 0x11 | 0x15 | 0x16 | 0x17 |
        0x18 | 0x19 | 0x1a | 0x1b => {
            *off = off.checked_add(varg + 1)?;
        }
        0x1c => { // VALUE_ARRAY
            let size = uleb128(dex, off)?;
            for _ in 0..size { skip_encoded_value(dex, off)?; }
        }
        0x1d => { // VALUE_ANNOTATION
            uleb128(dex, off)?; // type_idx
            let size = uleb128(dex, off)?;
            for _ in 0..size {
                uleb128(dex, off)?; // name_idx
                skip_encoded_value(dex, off)?;
            }
        }
        0x1e | 0x1f => {} // VALUE_NULL / VALUE_BOOLEAN — no extra bytes
        _ => return None,
    }
    Some(())
}

fn read_int_encoded_value(dex: &[u8], off: &mut usize) -> Option<u32> {
    let vbyte = *dex.get(*off)?;
    *off += 1;
    let vtype = vbyte & 0x1f;
    let varg  = (vbyte >> 5) as usize;
    // VALUE_INT = 0x04, value_arg+1 bytes, little-endian
    if vtype != 0x04 { return None; }
    let size = varg + 1;
    if size > 4 { return None; }
    let mut val = 0u32;
    for i in 0..size {
        val |= (*dex.get(*off + i)? as u32) << (i * 8);
    }
    *off += size;
    Some(val)
}

fn find_in_dex(dex: &[u8], class_desc: &[u8], field_name: &[u8]) -> Option<u32> {
    if !dex.starts_with(DEX_MAGIC) || dex.len() < 112 { return None; }

    let string_ids_size = u32le(dex, 56)? as usize;
    let string_ids_off  = u32le(dex, 60)? as usize;
    let type_ids_size   = u32le(dex, 64)? as usize;
    let type_ids_off    = u32le(dex, 68)? as usize;
    let field_ids_size  = u32le(dex, 80)? as usize;
    let field_ids_off   = u32le(dex, 84)? as usize;
    let class_defs_size = u32le(dex, 96)? as usize;
    let class_defs_off  = u32le(dex, 100)? as usize;

    // Find string index for class descriptor
    let mut class_str_idx: Option<usize> = None;
    for i in 0..string_ids_size {
        if dex_string(dex, string_ids_off, i) == Some(class_desc) {
            class_str_idx = Some(i);
            break;
        }
    }
    let class_str_idx = class_str_idx?;

    // Find type index
    let mut class_type_idx: Option<usize> = None;
    for i in 0..type_ids_size {
        if u32le(dex, type_ids_off + i * 4)? as usize == class_str_idx {
            class_type_idx = Some(i);
            break;
        }
    }
    let class_type_idx = class_type_idx?;

    // Find string index for field name
    let mut field_str_idx: Option<u32> = None;
    for i in 0..string_ids_size {
        if dex_string(dex, string_ids_off, i) == Some(field_name) {
            field_str_idx = Some(i as u32);
            break;
        }
    }
    let field_str_idx = field_str_idx?;

    // Find global field_idx in field_ids
    let mut target_field_idx: Option<u32> = None;
    for i in 0..field_ids_size {
        let foff = field_ids_off + i * 8;
        let fclass = u16le(dex, foff)? as usize;
        let fname  = u32le(dex, foff + 4)?;
        if fclass == class_type_idx && fname == field_str_idx {
            target_field_idx = Some(i as u32);
            break;
        }
    }
    let target_field_idx = target_field_idx?;

    // Find class def
    let mut class_data_off  = None;
    let mut static_vals_off = None;
    for i in 0..class_defs_size {
        let coff = class_defs_off + i * 32;
        if u32le(dex, coff)? as usize == class_type_idx {
            class_data_off  = Some(u32le(dex, coff + 24)? as usize);
            static_vals_off = Some(u32le(dex, coff + 28)? as usize);
            break;
        }
    }
    let class_data_off  = class_data_off?;
    let static_vals_off = static_vals_off?;
    if class_data_off == 0 || static_vals_off == 0 { return None; }

    // Walk class_data_item static fields to find position of target_field_idx
    let mut off = class_data_off;
    let static_fields_size  = uleb128(dex, &mut off)?;
    let _instance_fields    = uleb128(dex, &mut off)?;
    let _direct_methods     = uleb128(dex, &mut off)?;
    let _virtual_methods    = uleb128(dex, &mut off)?;

    let mut field_pos: Option<usize> = None;
    let mut cur_field_idx = 0u32;
    for i in 0..static_fields_size as usize {
        let diff         = uleb128(dex, &mut off)?;
        let _access_flags = uleb128(dex, &mut off)?;
        cur_field_idx += diff;
        if cur_field_idx == target_field_idx {
            field_pos = Some(i);
            break;
        }
    }
    let field_pos = field_pos?;

    // Read encoded_array at static_vals_off, skip to field_pos, read int
    let mut sv = static_vals_off;
    let sv_size = uleb128(dex, &mut sv)? as usize;
    if field_pos >= sv_size { return None; }

    for i in 0..=field_pos {
        if i == field_pos {
            return read_int_encoded_value(dex, &mut sv);
        }
        skip_encoded_value(dex, &mut sv)?;
    }
    None
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Search `framework.jar` for the value of a static int field.
///
/// `class_desc` uses DEX descriptor syntax, e.g.
/// `"Landroid/app/IActivityManager$Stub;"`.
///
/// Returns `None` if the JAR is unreadable, the class/field is absent, or
/// the entry is compressed (DEFLATE — not expected for framework DEX).
pub fn find_transaction_code(jar_path: &str, class_desc: &str, field_name: &str) -> Option<u32> {
    let data = std::fs::read(jar_path).ok()?;
    let entries = zip_find_dex_entries(&data);
    for entry in &entries {
        if let Some(dex) = zip_entry_data(&data, entry) {
            if let Some(code) = find_in_dex(dex, class_desc.as_bytes(), field_name.as_bytes()) {
                return Some(code);
            }
        }
    }
    None
}

/// Resolve all four tx codes needed for binder observer mode.
///
/// Returns `(observer_code, query_code, api_mode, fg_code)` where:
/// - `observer_code` = `TRANSACTION_registerProcessObserver`
/// - `query_code`    = `TRANSACTION_getFocusedRootTaskInfo` (or StackInfo on API 29)
/// - `api_mode`      = 1 (RootTaskInfo) or 2 (StackInfo)
/// - `fg_code`       = `TRANSACTION_onForegroundActivitiesChanged`
pub fn resolve_tx_codes_from_dex() -> Option<(u32, u32, u8, u32)> {
    const JAR: &str = "/system/framework/framework.jar";
    const AM_STUB:  &str = "Landroid/app/IActivityManager$Stub;";
    const OBS_STUB: &str = "Landroid/app/IProcessObserver$Stub;";

    let observer_code = find_transaction_code(JAR, AM_STUB, "TRANSACTION_registerProcessObserver")?;
    let fg_code = find_transaction_code(JAR, OBS_STUB, "TRANSACTION_onForegroundActivitiesChanged")?;

    if let Some(query_code) = find_transaction_code(JAR, AM_STUB, "TRANSACTION_getFocusedRootTaskInfo") {
        return Some((observer_code, query_code, 1, fg_code));
    }
    // API 29 fallback
    let query_code = find_transaction_code(JAR, AM_STUB, "TRANSACTION_getFocusedStackInfo")?;
    Some((observer_code, query_code, 2, fg_code))
}

/// Resolve `IPowerManager.isInteractive()` transaction code from DEX.
pub fn resolve_is_interactive_tx() -> Option<u32> {
    const JAR: &str = "/system/framework/framework.jar";
    find_transaction_code(JAR, "Landroid/os/IPowerManager$Stub;", "TRANSACTION_isInteractive")
}
