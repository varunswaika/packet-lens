//! A plain C ABI for the browser: no wasm-bindgen and no imports.
//!
//! The page copies the capture into memory from [`pl_alloc`], calls
//! [`pl_analyse`], reads the JSON reply and gives both buffers back with
//! [`pl_free`]. The reply is `{"ok": report}` or `{"error": "..."}`.

use serde_json::json;

/// Reserves `len` bytes and returns their address.
#[unsafe(no_mangle)]
pub extern "C" fn pl_alloc(len: usize) -> *mut u8 {
    let mut buffer = Vec::<u8>::with_capacity(len.max(1));
    let pointer = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    pointer
}

/// Releases `len` bytes from [`pl_alloc`] or [`pl_analyse`].
///
/// # Safety
/// `pointer` and `len` must describe one such buffer, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pl_free(pointer: *mut u8, len: usize) {
    drop(unsafe { Vec::from_raw_parts(pointer, 0, len.max(1)) });
}

/// Analyses the capture in the `len` bytes at `pointer`.
///
/// Returns a buffer holding the reply's length as a little-endian u32,
/// then the reply. Free it with `pl_free(p, 4 + length)`.
///
/// # Safety
/// `pointer` must be valid for reading `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pl_analyse(pointer: *const u8, len: usize) -> *mut u8 {
    let capture = unsafe { std::slice::from_raw_parts(pointer, len) };
    let reply = analyse(capture).into_bytes();
    let out = pl_alloc(4 + reply.len());
    unsafe {
        std::ptr::copy_nonoverlapping((reply.len() as u32).to_le_bytes().as_ptr(), out, 4);
        std::ptr::copy_nonoverlapping(reply.as_ptr(), out.add(4), reply.len());
    }
    out
}

pub fn analyse(capture: &[u8]) -> String {
    match packet_lens::analyse(capture) {
        Ok(report) => json!({ "ok": report }),
        Err(e) => json!({ "error": e.to_string() }),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_the_abi() {
        let capture = include_bytes!("../../../tests/fixtures/sll.pcap");
        unsafe {
            let input = pl_alloc(capture.len());
            std::ptr::copy_nonoverlapping(capture.as_ptr(), input, capture.len());
            let out = pl_analyse(input, capture.len());
            pl_free(input, capture.len());
            let len = u32::from_le_bytes(std::slice::from_raw_parts(out, 4).try_into().unwrap());
            let reply = std::slice::from_raw_parts(out.add(4), len as usize);
            let reply: serde_json::Value = serde_json::from_slice(reply).unwrap();
            pl_free(out, 4 + len as usize);
            assert_eq!(reply["ok"]["dns"][0]["name"], "sll.test");
        }
    }

    #[test]
    fn errors_come_back_as_json() {
        assert_eq!(analyse(b"nope"), r#"{"error":"not a pcap or pcapng file"}"#);
    }
}
