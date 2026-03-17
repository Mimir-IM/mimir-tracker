use std::collections::HashMap;
use std::io::{self, Write};

pub type TlvMap = HashMap<u8, Vec<u8>>;
#[allow(dead_code)]
pub type TlvMultiMap = HashMap<u8, Vec<Vec<u8>>>;

/// Write a varint (up to 4 bytes, 28 bits) using protobuf-style encoding.
pub fn write_varint<W: Write>(w: &mut W, mut value: u32) -> io::Result<()> {
    for _ in 0..4 {
        let mut b = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        w.write_all(&[b])?;
        if value == 0 {
            return Ok(());
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"))
}

/// Read a varint from a byte slice at offset, returns (value, bytes_consumed).
fn read_varint_from_bytes(data: &[u8], offset: usize) -> io::Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    for i in 0..4 {
        if offset + i >= data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "varint: unexpected end of data"));
        }
        let b = data[offset + i];
        result |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"))
}

/// Write a single TLV field.
pub fn write_tlv<W: Write>(w: &mut W, tag: u8, value: &[u8]) -> io::Result<()> {
    w.write_all(&[tag])?;
    write_varint(w, value.len() as u32)?;
    if !value.is_empty() {
        w.write_all(value)?;
    }
    Ok(())
}

/// Parse a TLV-encoded payload into a map of tag -> value.
/// Duplicate tags overwrite earlier values.
pub fn parse_tlvs(payload: &[u8]) -> io::Result<TlvMap> {
    let mut result = TlvMap::new();
    let mut offset = 0;

    while offset < payload.len() {
        let tag = payload[offset];
        offset += 1;

        let (length, consumed) = read_varint_from_bytes(payload, offset)?;
        offset += consumed;

        let length = length as usize;
        if offset + length > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tag 0x{:02X} length {} exceeds payload bounds", tag, length),
            ));
        }
        let value = payload[offset..offset + length].to_vec();
        offset += length;

        result.insert(tag, value);
    }

    Ok(result)
}

/// Parse a TLV-encoded payload, collecting all values for each tag.
/// Useful for repeated tags like TAG_RECORD.
#[allow(dead_code)]
pub fn parse_tlvs_multi(payload: &[u8]) -> io::Result<TlvMultiMap> {
    let mut result = TlvMultiMap::new();
    let mut offset = 0;

    while offset < payload.len() {
        let tag = payload[offset];
        offset += 1;

        let (length, consumed) = read_varint_from_bytes(payload, offset)?;
        offset += consumed;

        let length = length as usize;
        if offset + length > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tag 0x{:02X} length {} exceeds payload bounds", tag, length),
            ));
        }
        let value = payload[offset..offset + length].to_vec();
        offset += length;

        result.entry(tag).or_default().push(value);
    }

    Ok(result)
}

// ── Extraction helpers ───────────────────────────────────────────────────────

pub fn tlv_get_bytes(m: &TlvMap, tag: u8, expected_size: usize) -> Result<&[u8], String> {
    let val = m.get(&tag).ok_or_else(|| format!("missing required tag 0x{:02X}", tag))?;
    if expected_size > 0 && val.len() != expected_size {
        return Err(format!("tag 0x{:02X}: expected {} bytes, got {}", tag, expected_size, val.len()));
    }
    Ok(val)
}

pub fn tlv_get_u64(m: &TlvMap, tag: u8) -> Result<u64, String> {
    let val = tlv_get_bytes(m, tag, 8)?;
    Ok(u64::from_be_bytes(val.try_into().unwrap()))
}

pub fn tlv_get_u32(m: &TlvMap, tag: u8) -> Result<u32, String> {
    let val = tlv_get_bytes(m, tag, 4)?;
    Ok(u32::from_be_bytes(val.try_into().unwrap()))
}

pub fn tlv_get_u8(m: &TlvMap, tag: u8) -> Result<u8, String> {
    let val = tlv_get_bytes(m, tag, 1)?;
    Ok(val[0])
}

// ── Encoding helpers ─────────────────────────────────────────────────────────

pub fn tlv_encode_bytes<W: Write>(w: &mut W, tag: u8, value: &[u8]) -> io::Result<()> {
    write_tlv(w, tag, value)
}

pub fn tlv_encode_u64<W: Write>(w: &mut W, tag: u8, value: u64) -> io::Result<()> {
    write_tlv(w, tag, &value.to_be_bytes())
}

pub fn tlv_encode_u32<W: Write>(w: &mut W, tag: u8, value: u32) -> io::Result<()> {
    write_tlv(w, tag, &value.to_be_bytes())
}

pub fn tlv_encode_u8<W: Write>(w: &mut W, tag: u8, value: u8) -> io::Result<()> {
    write_tlv(w, tag, &[value])
}

/// Build a complete TLV payload using a closure that writes TLV fields.
pub fn build_tlv_payload<F>(build_fn: F) -> io::Result<Vec<u8>>
where
    F: FnOnce(&mut Vec<u8>) -> io::Result<()>,
{
    let mut buf = Vec::new();
    build_fn(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;

    #[test]
    fn test_varint_roundtrip() {
        for &val in &[0u32, 1, 127, 128, 16383, 16384, 0x0FFFFFFF] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val).unwrap();
            let (decoded, consumed) = read_varint_from_bytes(&buf, 0).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_tlv_roundtrip() {
        let mut buf = Vec::new();
        tlv_encode_u64(&mut buf, TAG_TTL_SECS, 42).unwrap();
        tlv_encode_bytes(&mut buf, TAG_USER_PUB, &[0xAA; 32]).unwrap();
        tlv_encode_u8(&mut buf, TAG_PRIORITY, 5).unwrap();

        let map = parse_tlvs(&buf).unwrap();
        assert_eq!(tlv_get_u64(&map, TAG_TTL_SECS).unwrap(), 42);
        assert_eq!(tlv_get_bytes(&map, TAG_USER_PUB, 32).unwrap(), &[0xAA; 32]);
        assert_eq!(tlv_get_u8(&map, TAG_PRIORITY).unwrap(), 5);
    }

    #[test]
    fn test_parse_empty() {
        let map = parse_tlvs(&[]).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_tlvs_multi() {
        let mut buf = Vec::new();
        tlv_encode_u8(&mut buf, TAG_COUNT, 2).unwrap();
        // Two TAG_RECORD entries
        let rec1 = vec![1, 2, 3];
        let rec2 = vec![4, 5, 6];
        tlv_encode_bytes(&mut buf, TAG_RECORD, &rec1).unwrap();
        tlv_encode_bytes(&mut buf, TAG_RECORD, &rec2).unwrap();

        let multi = parse_tlvs_multi(&buf).unwrap();
        assert_eq!(multi[&TAG_COUNT].len(), 1);
        assert_eq!(multi[&TAG_RECORD].len(), 2);
        assert_eq!(multi[&TAG_RECORD][0], rec1);
        assert_eq!(multi[&TAG_RECORD][1], rec2);
    }

    #[test]
    fn test_nested_record_tlv() {
        // Build a nested TLV record (as used in GET_ADDRS response)
        let inner = build_tlv_payload(|w| {
            tlv_encode_bytes(w, TAG_NODE_PUB, &[0xBB; 32])?;
            tlv_encode_bytes(w, TAG_SIGNATURE, &[0xCC; 64])?;
            tlv_encode_u8(w, TAG_PRIORITY, 3)?;
            tlv_encode_u32(w, TAG_CLIENT_ID, 1234)?;
            tlv_encode_u64(w, TAG_EXPIRES_MS, 60000)?;
            Ok(())
        }).unwrap();

        // Wrap in TAG_RECORD
        let mut outer = Vec::new();
        tlv_encode_bytes(&mut outer, TAG_RECORD, &inner).unwrap();

        // Parse outer, extract inner
        let map = parse_tlvs(&outer).unwrap();
        let record_bytes = tlv_get_bytes(&map, TAG_RECORD, 0).unwrap();
        let inner_map = parse_tlvs(record_bytes).unwrap();

        assert_eq!(tlv_get_bytes(&inner_map, TAG_NODE_PUB, 32).unwrap(), &[0xBB; 32]);
        assert_eq!(tlv_get_bytes(&inner_map, TAG_SIGNATURE, 64).unwrap(), &[0xCC; 64]);
        assert_eq!(tlv_get_u8(&inner_map, TAG_PRIORITY).unwrap(), 3);
        assert_eq!(tlv_get_u32(&inner_map, TAG_CLIENT_ID).unwrap(), 1234);
        assert_eq!(tlv_get_u64(&inner_map, TAG_EXPIRES_MS).unwrap(), 60000);
    }
}
