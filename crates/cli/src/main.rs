use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use packet_lens::Report;
use packet_lens::analysis::{FlowSummary, Traffic};

// Like std's println!, but a closed pipe (`packet-lens x.pcap | head`) ends the program quietly
// instead of panicking.
macro_rules! println {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        if writeln!(std::io::stdout().lock(), $($t)*).is_err() {
            std::process::exit(0);
        }
    }};
}

/// Sums up a pcap or pcapng capture: protocols, top talkers, flows with
/// TCP reassembly stats and TLS server names, and DNS queries.
#[derive(Parser)]
#[command(version)]
struct Args {
    file: PathBuf,
    /// Print the whole report as JSON.
    #[arg(long)]
    json: bool,
    /// Rows to show in each list.
    #[arg(short = 'n', long, default_value_t = 10)]
    top: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let bytes =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let report = packet_lens::analyse(&bytes).with_context(|| args.file.display().to_string())?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print(&report, &args.file.display().to_string(), args.top);
    }
    Ok(())
}

fn print(r: &Report, name: &str, top: usize) {
    let span = match (r.start_us, r.end_us) {
        (Some(a), Some(b)) => format!(", {}", duration(b - a)),
        _ => String::new(),
    };
    println!(
        "{name}: {}, {} packets, {}{span}",
        r.format,
        r.packets,
        size(r.bytes)
    );
    if let Some(error) = &r.error {
        println!("stopped early: {error}");
    }

    heading("Protocols", r.protocols.len(), r.protocols.len());
    for p in &r.protocols {
        println!(
            "  {:<12} {:<11} {:>8} pkts {:>9}",
            p.layer,
            p.name,
            p.packets,
            size(p.bytes)
        );
    }

    heading("Top talkers", r.talker_count, top);
    println!("  {:<40} {:>20} {:>20}", "", "sent", "received");
    for t in r.talkers.iter().take(top) {
        println!(
            "  {:<40} {:>20} {:>20}",
            t.addr,
            traffic(t.sent),
            traffic(t.received)
        );
    }

    heading("Flows, biggest first", r.flow_count, top);
    for f in r.flows.iter().take(top) {
        print_flow(f);
    }

    heading("DNS", r.dns_count, top);
    let start = r.start_us.unwrap_or_default();
    for d in r.dns.iter().take(top) {
        let rcode = d.rcode.unwrap_or("no reply");
        let latency = d
            .latency_us
            .map(|us| format!("{:.1} ms", us as f64 / 1000.0));
        let line = format!(
            "  {:>9}  {:<26} {:<5} {rcode:<9} {:>9}  {}  {}",
            duration(d.time_us.saturating_sub(start)),
            d.client,
            d.kind,
            latency.unwrap_or_default(),
            d.name,
            d.answers.join(", "),
        );
        println!("{}", line.trim_end());
    }
}

fn print_flow(f: &FlowSummary) {
    let ends = format!(
        "{} → {}",
        endpoint(f.client, f.client_port, f.protocol),
        endpoint(f.server, f.server_port, f.protocol)
    );
    let total = Traffic {
        packets: f.to_server.packets + f.to_client.packets,
        bytes: f.to_server.bytes + f.to_client.bytes,
    };
    let mut notes = Vec::new();
    if let Some(app) = f.app {
        notes.push(app.to_string());
    }
    if let Some(sni) = &f.sni {
        notes.push(sni.clone());
    }
    if let Some(tcp) = &f.tcp {
        notes.push(tcp.end.unwrap_or("open").to_string());
        let resent = tcp.to_server.retransmitted + tcp.to_client.retransmitted;
        let early = tcp.to_server.out_of_order + tcp.to_client.out_of_order;
        let missing = tcp.to_server.missing + tcp.to_client.missing;
        if resent > 0 {
            notes.push(format!("resent {}", size(resent)));
        }
        if early > 0 {
            notes.push(format!("{early} out of order"));
        }
        if missing > 0 {
            notes.push(format!("missing {}", size(missing)));
        }
    }
    println!(
        "  {:<6} {:<58} {:>20}  {}",
        f.protocol,
        ends,
        traffic(total),
        notes.join(", ")
    );
}

fn heading(title: &str, count: usize, shown: usize) {
    if count == 0 {
        println!("\n{title}: none");
    } else if count > shown {
        println!("\n{title} ({shown} of {count})");
    } else {
        println!("\n{title}");
    }
}

fn endpoint(addr: std::net::IpAddr, port: u16, protocol: &str) -> String {
    match (addr, protocol) {
        (_, "icmp" | "icmpv6") => addr.to_string(),
        (std::net::IpAddr::V6(a), _) => format!("[{a}]:{port}"),
        _ => format!("{addr}:{port}"),
    }
}

fn traffic(t: Traffic) -> String {
    format!("{} pkts {:>8}", t.packets, size(t.bytes))
}

fn size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["kB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1000.0;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn duration(us: u64) -> String {
    let s = us as f64 / 1e6;
    if s < 60.0 {
        format!("{s:.3} s")
    } else {
        format!("{}m {:02}s", us / 60_000_000, (us / 1_000_000) % 60)
    }
}
