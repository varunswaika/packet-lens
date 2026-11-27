//! Puts one direction of a TCP connection back in order: far enough to
//! count what was sent twice, what came early and what never came, and to
//! keep the first few kilobytes for spotting the protocol.

use std::collections::BTreeMap;

use serde::Serialize;

/// How much of the start of a stream is kept.
pub const PREFIX: usize = 16 * 1024;

/// Segments held past a gap before the gap is written off as lost. Keeps a
/// capture with heavy loss from holding every segment in memory.
const MAX_HELD: usize = 64;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StreamStats {
    /// Distinct payload bytes seen.
    pub bytes: u64,
    /// Payload bytes seen more than once.
    pub retransmitted: u64,
    /// Segments that arrived ahead of a gap.
    pub out_of_order: u64,
    /// Bytes inside gaps that never filled.
    pub missing: u64,
}

#[derive(Default)]
pub struct Stream {
    /// The sequence number of the first payload byte, once known.
    base: Option<u32>,
    /// Offset of the next byte in order.
    next: u64,
    /// Segments past a gap, by offset.
    held: BTreeMap<u64, Held>,
    keep: bool,
    prefix: Vec<u8>,
    stats: StreamStats,
}

struct Held {
    len: u64,
    /// The part of the segment that falls inside the prefix.
    data: Vec<u8>,
}

impl Stream {
    pub fn new(keep_prefix: bool) -> Self {
        Stream {
            keep: keep_prefix,
            ..Stream::default()
        }
    }

    pub fn syn(&mut self, seq: u32) {
        if self.next == 0 && self.held.is_empty() {
            self.base = Some(seq.wrapping_add(1));
        }
    }

    pub fn segment(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        // With no SYN in the capture, the stream starts at the first data.
        let base = *self.base.get_or_insert(seq);
        let len = payload.len() as u64;
        let Some(start) = self.offset(base, seq) else {
            self.stats.retransmitted += len;
            return;
        };
        if start + len <= self.next {
            self.stats.retransmitted += len;
        } else if start > self.next {
            self.hold(start, payload);
        } else {
            let seen = self.next - start;
            self.stats.retransmitted += seen;
            self.deliver(&payload[seen as usize..], len - seen);
            self.drain();
        }
    }

    /// Writes off any gaps still open and returns the totals.
    pub fn finish(&mut self) -> StreamStats {
        while !self.held.is_empty() {
            self.skip_gap();
        }
        self.stats
    }

    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    pub fn prefix_is_full(&self) -> bool {
        self.prefix.len() == PREFIX
    }

    pub fn drop_prefix(&mut self) {
        self.keep = false;
        self.prefix = Vec::new();
    }

    /// Sequence numbers wrap at 2^32, so take the offset nearest the next
    /// byte expected. `None` if that falls before the stream began.
    fn offset(&self, base: u32, seq: u32) -> Option<u64> {
        let delta = seq.wrapping_sub(base).wrapping_sub(self.next as u32) as i32;
        self.next.checked_add_signed(i64::from(delta))
    }

    fn deliver(&mut self, data: &[u8], len: u64) {
        if self.keep && self.prefix.len() as u64 == self.next {
            let room = PREFIX - self.prefix.len();
            self.prefix.extend_from_slice(&data[..data.len().min(room)]);
        }
        self.next += len;
        self.stats.bytes += len;
    }

    fn hold(&mut self, start: u64, payload: &[u8]) {
        let len = payload.len() as u64;
        if self.held.get(&start).is_some_and(|h| h.len >= len) {
            self.stats.retransmitted += len;
            return;
        }
        self.stats.out_of_order += 1;
        let kept = if self.keep {
            (PREFIX as u64).saturating_sub(start).min(len) as usize
        } else {
            0
        };
        let data = payload[..kept].to_vec();
        self.held.insert(start, Held { len, data });
        if self.held.len() > MAX_HELD {
            self.skip_gap();
        }
    }

    /// Moves past the bytes in the gap: they count as missing.
    fn skip_gap(&mut self) {
        if let Some(&start) = self.held.keys().next() {
            self.stats.missing += start.saturating_sub(self.next);
            self.next = self.next.max(start);
            self.drain();
        }
    }

    fn drain(&mut self) {
        while let Some(entry) = self.held.first_entry() {
            let start = *entry.key();
            if start > self.next {
                break;
            }
            let held = entry.remove();
            let seen = (self.next - start).min(held.len);
            self.stats.retransmitted += seen;
            let data = held.data.get(seen as usize..).unwrap_or_default();
            self.deliver(data, held.len - seen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order() {
        let mut s = Stream::new(true);
        s.syn(100);
        s.segment(101, b"hello ");
        s.segment(107, b"world");
        assert_eq!(s.prefix(), b"hello world");
        assert_eq!(
            s.finish(),
            StreamStats {
                bytes: 11,
                ..StreamStats::default()
            }
        );
    }

    #[test]
    fn early_segment_waits_for_the_gap() {
        let mut s = Stream::new(true);
        s.syn(0);
        s.segment(7, b"world");
        assert_eq!(s.prefix(), b"");
        s.segment(1, b"hello ");
        assert_eq!(s.prefix(), b"hello world");
        let stats = s.finish();
        assert_eq!((stats.bytes, stats.out_of_order, stats.missing), (11, 1, 0));
    }

    #[test]
    fn resends_and_overlaps() {
        let mut s = Stream::new(true);
        s.syn(0);
        s.segment(1, b"abcd");
        s.segment(1, b"abcd");
        s.segment(3, b"cdef");
        assert_eq!(s.prefix(), b"abcdef");
        let stats = s.finish();
        assert_eq!((stats.bytes, stats.retransmitted), (6, 6));
    }

    #[test]
    fn sequence_numbers_wrap() {
        let mut s = Stream::new(true);
        s.syn(u32::MAX - 2);
        s.segment(u32::MAX - 1, b"abc");
        s.segment(1, b"def");
        assert_eq!(s.prefix(), b"abcdef");
    }

    #[test]
    fn capture_starting_mid_stream() {
        let mut s = Stream::new(false);
        s.segment(5000, b"later");
        s.segment(4990, b"earlier");
        let stats = s.finish();
        assert_eq!((stats.bytes, stats.retransmitted), (5, 7));
    }

    #[test]
    fn gaps_that_never_fill() {
        let mut s = Stream::new(true);
        s.syn(0);
        s.segment(1, b"ab");
        s.segment(10, b"xyz");
        let stats = s.finish();
        assert_eq!((stats.bytes, stats.missing), (5, 7));
        assert_eq!(s.prefix(), b"ab");
    }

    #[test]
    fn heavy_loss_does_not_hold_everything() {
        let mut s = Stream::new(false);
        s.syn(0);
        for i in 0..1000u32 {
            s.segment(1 + 20 * i + 10, &[0; 10]);
        }
        assert!(s.held.len() <= MAX_HELD);
        let stats = s.finish();
        assert_eq!((stats.bytes, stats.missing), (10_000, 10_000));
    }

    #[test]
    fn prefix_stops_at_its_limit() {
        let mut s = Stream::new(true);
        s.syn(0);
        let chunk = [7; 1000];
        for i in 0..20u32 {
            s.segment(1 + 1000 * i, &chunk);
        }
        assert!(s.prefix_is_full());
        assert_eq!(s.finish().bytes, 20_000);
    }
}
