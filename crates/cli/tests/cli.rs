use std::process::Command;

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_packet-lens"))
        .args(args)
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures"))
        .output()
        .unwrap();
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
    (out.status.success(), text(out.stdout), text(out.stderr))
}

#[test]
fn summary() {
    let (ok, out, _) = run(&["tls.pcap"]);
    assert!(ok);
    assert!(out.starts_with("tls.pcap: pcap, 7 packets"));
    assert!(out.contains("tls, packet-lens.test, rst, resent 761 B, 1 out of order"));
    assert!(out.contains("DNS: none"));
}

#[test]
fn json() {
    let (ok, out, _) = run(&["--json", "mixed.pcapng"]);
    assert!(ok);
    assert!(out.contains(r#""format": "pcapng""#));
    assert!(out.contains(r#""name": "nope.invalid""#));
}

#[test]
fn not_a_capture() {
    let (ok, _, err) = run(&["make.py"]);
    assert!(!ok);
    assert!(err.contains("not a pcap or pcapng file"));
}
