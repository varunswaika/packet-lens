// Runs the built WebAssembly module through the same loader the page uses.
// Needs `make web` first.
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { test } from "node:test"

import { loadLens } from "../web/lens.js"

const fixture = (name) => readFileSync(new URL(`fixtures/${name}`, import.meta.url))
const analyse = await loadLens(readFileSync(new URL("../web/packet_lens.wasm", import.meta.url)))

test("reads the sample", () => {
  const r = analyse(fixture("sample.pcap"))
  assert.equal(r.packets, 28)
  assert.equal(r.flows.find((f) => f.server_port === 443).sni, "packet-lens.test")
  assert.deepEqual(
    r.dns.map((d) => d.name),
    ["www.example.com", "example.com", "nope.invalid"],
  )
})

test("times survive the trip through JSON", () => {
  const r = analyse(fixture("mixed-ns.pcap"))
  assert.equal(r.start_us, 1_790_000_000_000_000)
  assert.equal(r.end_us - r.start_us, 1_400_000)
})

test("errors come back as exceptions", () => {
  assert.throws(() => analyse(new TextEncoder().encode("hello")), /not a pcap or pcapng file/)
  assert.throws(() => analyse(new Uint8Array(0)), /not a pcap or pcapng file/)
})
