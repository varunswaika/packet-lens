//! Parses DNS messages: the header, questions, and the answers worth
//! showing (addresses and names).

use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bytes::{array, be16, be32, u8_at};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub kind: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub name: String,
    pub kind: u16,
    pub ttl: u32,
    pub data: Data,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// CNAME, NS and PTR records all hold one name.
    Name(String),
    Other,
}

impl Answer {
    pub fn describe(&self) -> String {
        match &self.data {
            Data::A(a) => a.to_string(),
            Data::Aaaa(a) => a.to_string(),
            Data::Name(n) => format!("{} {n}", kind_name(self.kind)),
            Data::Other => kind_name(self.kind).to_string(),
        }
    }
}

// Questions and answers past these are not read. Real messages have one
// question and a handful of answers.
const MAX_QUESTIONS: u16 = 8;
const MAX_ANSWERS: u16 = 32;

pub fn parse(msg: &[u8]) -> Option<Message> {
    let header = array::<12>(msg, 0)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let count = |at: usize| u16::from_be_bytes([header[at], header[at + 1]]);
    // The opcode must be a standard query, or this is probably not DNS.
    if (flags >> 11) & 0xf != 0 {
        return None;
    }

    let mut at = 12;
    let mut questions = Vec::new();
    for _ in 0..count(4).min(MAX_QUESTIONS) {
        let (name, end) = name(msg, at)?;
        questions.push(Question {
            name,
            kind: be16(msg, end)?,
        });
        at = end + 4;
    }
    if count(4) > MAX_QUESTIONS {
        return None;
    }

    let mut answers = Vec::new();
    for _ in 0..count(6).min(MAX_ANSWERS) {
        let (owner, end) = name(msg, at)?;
        let kind = be16(msg, end)?;
        let ttl = be32(msg, end + 4)?;
        let len = usize::from(be16(msg, end + 8)?);
        let start = end + 10;
        let rdata = msg.get(start..start + len)?;
        let data = match kind {
            1 => array::<4>(rdata, 0).map_or(Data::Other, |a| Data::A(a.into())),
            28 => array::<16>(rdata, 0).map_or(Data::Other, |a| Data::Aaaa(a.into())),
            2 | 5 | 12 => name(msg, start).map_or(Data::Other, |(n, _)| Data::Name(n)),
            _ => Data::Other,
        };
        answers.push(Answer {
            name: owner,
            kind,
            ttl,
            data,
        });
        at = start + len;
    }

    Some(Message {
        id: u16::from_be_bytes([header[0], header[1]]),
        response: flags & 0x8000 != 0,
        rcode: (flags & 0xf) as u8,
        questions,
        answers,
    })
}

/// Reads the name at `at`, following compression pointers. Returns it with
/// the offset just past the name where it first appears.
fn name(msg: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    let mut wire_len = 0;
    loop {
        let len = u8_at(msg, at)?;
        match len >> 6 {
            0 if len == 0 => break,
            0 => {
                let label = msg.get(at + 1..at + 1 + usize::from(len))?;
                wire_len += label.len() + 1;
                if wire_len > 255 {
                    return None;
                }
                push_label(&mut out, label);
                at += 1 + label.len();
            }
            3 => {
                let target = usize::from(be16(msg, at)? & 0x3fff);
                // Only jumping backwards guarantees the walk ends.
                if target >= at {
                    return None;
                }
                end.get_or_insert(at + 2);
                at = target;
            }
            _ => return None,
        }
    }
    if out.is_empty() {
        out.push('.');
    }
    Some((out, end.unwrap_or(at + 1)))
}

fn push_label(out: &mut String, label: &[u8]) {
    if !out.is_empty() {
        out.push('.');
    }
    for &b in label {
        match b {
            b'.' | b'\\' => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x21..=0x7e => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "\\{b:03}");
            }
        }
    }
}

pub fn kind_name(kind: u16) -> &'static str {
    match kind {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        _ => "other",
    }
}

pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, name: &[u8], kind: u16) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        m.extend(name);
        m.extend(kind.to_be_bytes());
        m.extend([0, 1]);
        m
    }

    const EXAMPLE: &[u8] = b"\x03www\x07example\x03com\x00";

    #[test]
    fn query_name_and_type() {
        let m = parse(&query(7, EXAMPLE, 28)).unwrap();
        assert!(!m.response);
        assert_eq!(m.id, 7);
        assert_eq!(m.questions[0].name, "www.example.com");
        assert_eq!(kind_name(m.questions[0].kind), "AAAA");
    }

    #[test]
    fn compressed_answers() {
        let mut m = query(7, EXAMPLE, 1);
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 2;
        // CNAME www.example.com -> example.com (a pointer to offset 16)
        m.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 1, 44, 0, 2, 0xc0, 16]);
        // A example.com 192.0.2.7
        m.extend([0xc0, 16, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
        let m = parse(&m).unwrap();
        assert!(m.response);
        let got: Vec<_> = m.answers.iter().map(Answer::describe).collect();
        assert_eq!(got, ["CNAME example.com", "192.0.2.7"]);
        assert_eq!(m.answers[1].name, "example.com");
        assert_eq!(m.answers[0].ttl, 300);
    }

    #[test]
    fn pointer_loops_are_refused() {
        // The name points at itself.
        let m = query(1, &[0xc0, 12], 1);
        assert_eq!(parse(&m), None);
        // A pointer forward, to a pointer back.
        assert_eq!(parse(&query(1, &[0xc0, 14, 0xc0, 12], 1)), None);
    }

    #[test]
    fn odd_bytes_in_labels_are_escaped() {
        let m = parse(&query(1, b"\x03a.b\x02\x00\xff\x00", 1)).unwrap();
        assert_eq!(m.questions[0].name, "a\\.b.\\000\\255");
        let root = parse(&query(1, b"\x00", 2)).unwrap();
        assert_eq!(root.questions[0].name, ".");
    }

    #[test]
    fn never_panics_on_any_cut() {
        let mut m = query(7, EXAMPLE, 1);
        m[7] = 1;
        m.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 1, 44, 0, 2, 0xc0, 16]);
        assert_eq!(parse(&m).unwrap().answers.len(), 1);
        for cut in 0..m.len() {
            assert!(parse(&m[..cut]).is_none_or(|m| m.answers.is_empty()));
        }
    }
}
