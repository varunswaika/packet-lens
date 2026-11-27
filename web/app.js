import { loadLens } from "./lens.js"

const ROWS = 100
const $ = (selector) => document.querySelector(selector)
const count = new Intl.NumberFormat("en-AU")

const lens = fetch("packet_lens.wasm")
  .then((r) => {
    if (!r.ok) throw new Error("packet_lens.wasm is missing: run `make web` first")
    return r.arrayBuffer()
  })
  .then(loadLens)

async function open(name, bytes) {
  const results = $("#results")
  results.replaceChildren(el("p", { class: "note" }, `Reading ${name}…`))
  try {
    const analyse = await lens
    const started = performance.now()
    const report = analyse(new Uint8Array(bytes))
    const took = performance.now() - started
    results.replaceChildren(...render(report, name, took))
    document.body.classList.add("loaded")
  } catch (e) {
    results.replaceChildren(el("p", { class: "error" }, `${name}: ${e.message}`))
  }
}

function render(r, name, took) {
  const span = r.start_us != null ? seconds(r.end_us - r.start_us) : "no timestamps"
  const start = r.start_us ?? 0
  return [
    el(
      "header",
      { class: "summary" },
      el("h2", {}, name),
      el(
        "p",
        {},
        `${r.format} · ${count.format(r.packets)} packets · ${size(r.bytes)} · ${span}`,
        el("span", { class: "quiet" }, ` · read in ${took.toFixed(0)} ms`),
      ),
      r.error && el("p", { class: "error" }, `Stopped early: ${r.error}`),
    ),
    section("Protocols", r.protocols.length, protocols(r)),
    section("Top talkers", r.talker_count, talkers(r)),
    section("Flows", r.flow_count, flows(r), "biggest first"),
    section("DNS queries", r.dns_count, dns(r, start)),
  ]
}

function section(title, total, table, note) {
  const shown = Math.min(total, ROWS)
  const parts = [note, total > shown && `${shown} of ${count.format(total)} shown`].filter(Boolean)
  return el(
    "section",
    {},
    el("h3", {}, title, parts.length > 0 && el("span", { class: "quiet" }, ` · ${parts.join(", ")}`)),
    total === 0 ? el("p", { class: "quiet" }, "None in this capture.") : table,
  )
}

function protocols(r) {
  let layer = null
  return table(
    ["Layer", "Protocol", "Packets", "Bytes", ""],
    r.protocols.map((p) => {
      const first = p.layer !== layer
      layer = p.layer
      return [
        first ? p.layer : "",
        p.name,
        num(p.packets),
        num(size(p.bytes)),
        bar(p.packets / r.packets),
      ]
    }),
  )
}

function talkers(r) {
  const most = r.talkers.length > 0 ? total(r.talkers[0]) : 1
  return table(
    ["Address", "Sent", "", "Received", "", ""],
    r.talkers.slice(0, ROWS).map((t) => [
      el("code", {}, t.addr),
      num(pkts(t.sent.packets)),
      num(size(t.sent.bytes)),
      num(pkts(t.received.packets)),
      num(size(t.received.bytes)),
      bar(total(t) / most),
    ]),
  )
}

function flows(r) {
  return table(
    ["", "Client", "Server", "Packets", "Bytes", "Time", "What", "TCP"],
    r.flows.slice(0, ROWS).map((f) => [
      f.protocol,
      el("code", {}, endpoint(f.client, f.client_port, f.protocol)),
      el("code", {}, endpoint(f.server, f.server_port, f.protocol)),
      num(f.to_server.packets + f.to_client.packets),
      num(size(f.to_server.bytes + f.to_client.bytes)),
      num(seconds(f.end_us - f.start_us)),
      what(f),
      f.tcp && tcpNotes(f.tcp),
    ]),
  )
}

function what(f) {
  if (f.sni) return el("span", {}, `${f.app} `, el("strong", {}, f.sni))
  return f.app ?? ""
}

function tcpNotes(tcp) {
  const up = tcp.to_server
  const down = tcp.to_client
  const notes = [tcp.end ?? "open"]
  if (!tcp.syn) notes.push("no SYN")
  const resent = up.retransmitted + down.retransmitted
  const early = up.out_of_order + down.out_of_order
  const missing = up.missing + down.missing
  if (resent > 0) notes.push(`resent ${size(resent)}`)
  if (early > 0) notes.push(`${early} out of order`)
  if (missing > 0) notes.push(`missing ${size(missing)}`)
  const warn = resent + early + missing > 0
  return el("span", { class: warn ? "warn" : "quiet" }, notes.join(", "))
}

function dns(r, start) {
  return table(
    ["Time", "Client", "Type", "Name", "Result", "Answers", "Took"],
    r.dns.slice(0, ROWS).map((d) => [
      num(seconds(d.time_us - start)),
      el("code", {}, d.client),
      d.kind,
      el("code", {}, d.name),
      el("span", { class: d.rcode === "NOERROR" ? "" : "warn" }, d.rcode ?? "no reply"),
      d.answers.join(", "),
      num(d.latency_us != null ? `${(d.latency_us / 1000).toFixed(1)} ms` : ""),
    ]),
  )
}

function table(headings, rows) {
  // A column of numbers gets a right-aligned heading too.
  const numeric = (i) => rows[0]?.[i]?.classList?.contains("num")
  return el(
    "div",
    { class: "scroll" },
    el(
      "table",
      {},
      el("thead", {}, el("tr", {}, headings.map((h, i) => el("th", numeric(i) ? { class: "num" } : {}, h)))),
      el(
        "tbody",
        {},
        rows.map((cells) => el("tr", {}, cells.map((c) => (c instanceof Node && c.tagName === "TD" ? c : el("td", {}, c))))),
      ),
    ),
  )
}

const num = (value) => el("td", { class: "num" }, String(value))
const bar = (share) => {
  const fill = el("span", { class: "fill" })
  fill.style.width = `${Math.max(1, Math.round(share * 100))}%`
  return el("td", { class: "bar" }, fill)
}
const pkts = (n) => `${count.format(n)} ${n === 1 ? "pkt" : "pkts"}`
const total = (t) => t.sent.bytes + t.received.bytes

function endpoint(addr, port, protocol) {
  if (protocol.startsWith("icmp")) return addr
  return addr.includes(":") ? `[${addr}]:${port}` : `${addr}:${port}`
}

function size(bytes) {
  if (bytes < 1000) return `${bytes} B`
  const units = ["kB", "MB", "GB", "TB"]
  let value = bytes / 1000
  let unit = 0
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000
    unit += 1
  }
  return `${value.toFixed(1)} ${units[unit]}`
}

function seconds(us) {
  const s = us / 1e6
  return s < 60 ? `${s.toFixed(3)} s` : `${Math.floor(s / 60)}m ${String(Math.floor(s % 60)).padStart(2, "0")}s`
}

// Builds elements from text only, so names from a capture are never parsed as HTML.
function el(tag, attrs, ...children) {
  const node = document.createElement(tag)
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value)
  for (const child of children.flat()) {
    if (child == null || child === false || child === "") continue
    node.append(child instanceof Node ? child : String(child))
  }
  return node
}

function openFile(file) {
  if (file) file.arrayBuffer().then((bytes) => open(file.name, bytes))
}

$("#file").addEventListener("change", (e) => openFile(e.target.files[0]))
$("#sample").addEventListener("click", async () => {
  const r = await fetch("sample.pcap")
  if (r.ok) open("sample.pcap", await r.arrayBuffer())
  else $("#results").replaceChildren(el("p", { class: "error" }, "sample.pcap is missing: run `make web` first"))
})
document.addEventListener("dragover", (e) => {
  e.preventDefault()
  document.body.classList.add("dragging")
})
document.addEventListener("dragleave", (e) => {
  if (e.relatedTarget == null) document.body.classList.remove("dragging")
})
document.addEventListener("drop", (e) => {
  e.preventDefault()
  document.body.classList.remove("dragging")
  openFile(e.dataTransfer.files[0])
})
