// Runs the analysis compiled to WebAssembly. The capture is copied into the
// module's memory and the report comes back as JSON; nothing is sent anywhere.

export async function loadLens(wasmBytes) {
  const { instance } = await WebAssembly.instantiate(wasmBytes)
  const { memory, pl_alloc, pl_analyse, pl_free } = instance.exports

  return function analyse(capture) {
    const input = pl_alloc(capture.length) >>> 0
    new Uint8Array(memory.buffer, input, capture.length).set(capture)
    const out = pl_analyse(input, capture.length) >>> 0
    pl_free(input, capture.length)
    // Read the buffer only after the call: memory may have grown.
    const len = new DataView(memory.buffer).getUint32(out, true)
    const text = new TextDecoder().decode(new Uint8Array(memory.buffer, out + 4, len))
    pl_free(out, 4 + len)
    const reply = JSON.parse(text)
    if ("error" in reply) throw new Error(reply.error)
    return reply.ok
  }
}
