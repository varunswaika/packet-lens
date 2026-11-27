//! Bounds-checked reads. Every parser reads through these, so a short or
//! hostile input gives `None` instead of a panic.

pub fn array<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}

pub fn u8_at(b: &[u8], at: usize) -> Option<u8> {
    b.get(at).copied()
}

pub fn be16(b: &[u8], at: usize) -> Option<u16> {
    array(b, at).map(u16::from_be_bytes)
}

pub fn be32(b: &[u8], at: usize) -> Option<u32> {
    array(b, at).map(u32::from_be_bytes)
}

/// Byte order of a capture file, which is whatever the writer's machine used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Little,
    Big,
}

impl Order {
    pub fn u16(self, b: &[u8], at: usize) -> Option<u16> {
        let a = array(b, at)?;
        Some(match self {
            Order::Little => u16::from_le_bytes(a),
            Order::Big => u16::from_be_bytes(a),
        })
    }

    pub fn u32(self, b: &[u8], at: usize) -> Option<u32> {
        let a = array(b, at)?;
        Some(match self {
            Order::Little => u32::from_le_bytes(a),
            Order::Big => u32::from_be_bytes(a),
        })
    }
}
