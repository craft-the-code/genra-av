//! VBA project reading per [MS-OVBA]: the RLE-style decompression (2.4.1) and the `dir` stream
//! records that say which stream holds each module and where its source starts.
//! Nothing here executes code: it turns compressed bytes into source text for matching.

use anyhow::{bail, Result};

/// [MS-OVBA] 2.4.1.3.1 Decompression. `data` is a CompressedContainer (signature byte 0x01).
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    if data.first() != Some(&0x01) {
        bail!("not a compressed VBA container");
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len() * 2);
    let mut pos = 1;
    while pos + 2 <= data.len() {
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let chunk_start = pos;
        pos += 2;
        let chunk_size = (header & 0x0FFF) as usize + 3;
        let compressed = header & 0x8000 != 0;
        let chunk_end = (chunk_start + chunk_size).min(data.len());
        let out_chunk_start = out.len();
        if !compressed {
            let end = (pos + 4096).min(data.len());
            out.extend_from_slice(&data[pos..end]);
            pos = end;
            continue;
        }
        while pos < chunk_end {
            let flags = data[pos];
            pos += 1;
            for bit in 0..8 {
                if pos >= chunk_end {
                    break;
                }
                if flags >> bit & 1 == 0 {
                    out.push(data[pos]);
                    pos += 1;
                    continue;
                }
                if pos + 2 > chunk_end {
                    bail!("truncated copy token");
                }
                let token = u16::from_le_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                let diff = out.len() - out_chunk_start;
                let mut bit_count = 4u32;
                while (1usize << bit_count) < diff && bit_count < 12 {
                    bit_count += 1;
                }
                let length_mask = 0xFFFFu16 >> bit_count;
                let length = (token & length_mask) as usize + 3;
                let offset = ((token & !length_mask) >> (16 - bit_count)) as usize + 1;
                if offset > diff {
                    bail!("copy token points before the chunk");
                }
                let from = out.len() - offset;
                for i in 0..length {
                    let b = out[from + i];
                    out.push(b);
                }
            }
        }
        pos = chunk_end;
    }
    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct ModuleRef {
    pub name: String,
    pub stream_name: String,
    pub text_offset: u32,
}

/// Reads the module list out of a decompressed `dir` stream ([MS-OVBA] 2.3.4.2).
/// Records are `id u16, size u32, data`; PROJECTVERSION (0x0009) is the one record whose size
/// field does not cover its data (it is a reserved 4 followed by 6 bytes).
pub fn modules(dir: &[u8]) -> Vec<ModuleRef> {
    let mut found = Vec::new();
    let mut current: Option<ModuleRef> = None;
    let mut pos = 0;
    while pos + 6 <= dir.len() {
        let id = u16::from_le_bytes([dir[pos], dir[pos + 1]]);
        let size = u32::from_le_bytes([dir[pos + 2], dir[pos + 3], dir[pos + 4], dir[pos + 5]]) as usize;
        pos += 6;
        if id == 0x0009 {
            pos += 6;
            continue;
        }
        if pos + size > dir.len() {
            break;
        }
        let data = &dir[pos..pos + size];
        pos += size;
        match id {
            0x0019 => current = Some(ModuleRef { name: latin1(data), ..Default::default() }),
            0x001A => {
                if let Some(m) = current.as_mut() {
                    m.stream_name = latin1(data);
                }
            }
            0x0031 if data.len() >= 4 => {
                if let Some(m) = current.as_mut() {
                    m.text_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                }
            }
            0x002B => {
                if let Some(m) = current.take() {
                    found.push(m);
                }
            }
            0x0010 => break,
            _ => {}
        }
    }
    found
}

/// Module and stream names are MBCS in the project code page; for matching ASCII names and
/// keywords a byte-to-char mapping is enough and never fails.
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // [MS-OVBA] 3.2.1 example: "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
    #[test]
    fn decompresses_spec_example() {
        let compressed = [
            0x01u8, 0x2F, 0xB0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66, 0x00,
            0x70, 0x61, 0x67, 0x68, 0x69, 0x6A, 0x01, 0x38, 0x08, 0x61, 0x6B, 0x6C, 0x00, 0x30, 0x6D,
            0x6E, 0x6F, 0x70, 0x06, 0x71, 0x02, 0x70, 0x04, 0x10, 0x72, 0x73, 0x74, 0x75, 0x76, 0x10,
            0x77, 0x78, 0x79, 0x7A, 0x00, 0x3C,
        ];
        let out = decompress(&compressed).unwrap();
        assert_eq!(String::from_utf8_lossy(&out), "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa");
    }

    #[test]
    fn rejects_non_container() {
        assert!(decompress(&[0x00, 0x01]).is_err());
    }
}
