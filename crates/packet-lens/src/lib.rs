//! Reads pcap and pcapng captures and sums up what is in them: protocols,
//! top talkers, flows with TCP reassembly stats, TLS server names and a DNS
//! log. Pure Rust with no I/O, so the same code runs in the CLI and, built
//! to WebAssembly, in the browser.

pub mod analysis;
mod bytes;
pub mod capture;
pub mod decode;
pub mod dns;
pub mod stream;
pub mod tls;

pub use analysis::Report;
pub use capture::Error;

/// Reads a whole capture. Fails only if the bytes are not a capture at all;
/// a file that is cut short gives a report of what came before the cut,
/// with `error` saying where.
pub fn analyse(bytes: &[u8]) -> Result<Report, Error> {
    let capture = capture::open(bytes)?;
    let mut analyser = analysis::Analyser::new(capture.format());
    for frame in capture {
        match frame {
            Ok(frame) => analyser.add(&frame),
            Err(e) => analyser.stopped(e.to_string()),
        }
    }
    Ok(analyser.finish())
}
