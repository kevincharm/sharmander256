// Ref: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

// SHA-224 & SHA-256 constants only
// First 32 bits of the fractional parts of the cube roots of the first 64 prime numbers
const K: readonly number[] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

// FIPS 180-4 5.3.3
// SHA-256 IV
const H0: readonly number[] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

// Utility functions
const toNum = (x: bigint) => {
    if (x > Number.MAX_SAFE_INTEGER) throw new Error(`Number overflow: ${x}`)
    return Number(x)
}
const u32 = (x: number) => x >>> 0
const mod = (x: bigint, n: bigint) => ((x % n) + n) % n

// FIPS 180-4 3.2, 4.1.2
const rotr = (x: number, n: number) => u32((x >>> n) | (x << (32 - n)))
const ch = (x: number, y: number, z: number) => u32((x & y) ^ (~x & z))
const maj = (x: number, y: number, z: number) => u32((x & y) ^ (x & z) ^ (y & z))
const bigsig0 = (x: number) => u32(rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
const bigsig1 = (x: number) => u32(rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
const lilsig0 = (x: number) => u32(rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3))
const lilsig1 = (x: number) => u32(rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10))

/**
 * Pad message s.t. its length is a multiple of 512 bits
 * FIPS 180-4 5.1
 *
 * @param message Message to pad
 * @returns Padded message, reading for parsing
 */
function pad(message: Uint8Array): Uint8Array {
    // length of message in BITS
    const l = BigInt(message.byteLength) * 8n
    // 1. Set single bit after message (i.e. append 0x80)
    message = new Uint8Array([...message, 0x80])
    // 2. Append zero bits until message length is 64 bits short of a multiple of 512
    const k = toNum(mod(448n - l - 8n, 512n) / 8n)
    const zeroPad = Uint8Array.from({ length: k }, () => 0x00)
    message = new Uint8Array([...message, ...zeroPad])
    // 3. Append 64-bit uint representing the byte length of the message
    const len = Uint8Array.from({ length: 8 }, () => 0x00)
    // NB: big-endian
    len[0] = toNum((l >> 56n) & 0xffn)
    len[1] = toNum((l >> 48n) & 0xffn)
    len[2] = toNum((l >> 40n) & 0xffn)
    len[3] = toNum((l >> 32n) & 0xffn)
    len[4] = toNum((l >> 24n) & 0xffn)
    len[5] = toNum((l >> 16n) & 0xffn)
    len[6] = toNum((l >> 8n) & 0xffn)
    len[7] = toNum(l & 0xffn)
    message = new Uint8Array([...message, ...len])
    if (message.byteLength % 64 !== 0) throw new Error(`Invalid padding: ${message.byteLength}B`)
    return message
}

/**
 * Process an already-padded message into 512-bit blocks
 * FIPS 180-4 5.2
 *
 * @param message Padded message
 * @returns List of 512-bit message blocks, ready for computation
 */
function parse(message: Uint8Array): Uint8Array[] {
    const blocks: Uint8Array[] = []
    for (let i = 0; i < message.byteLength; i += 64) {
        const block = message.slice(i, i + 64)
        blocks.push(block)
        if (block.byteLength !== 64) throw new Error(`Invalid block length: ${block.byteLength}B`)
    }
    return blocks
}

/**
 * Compute SHA-256 digest of already-parsed message blocks
 * FIPS 180-4 6.2
 *
 * @param blocks 512-bit message blocks
 * @returns SHA-256 digest bytearray
 */
function compute(blocks: Uint8Array[]): Uint8Array {
    // Start with the SHA-256 initial vector
    const output: number[] = [...H0] // NB: copy IV into output
    for (const m of blocks) {
        // Message schedule W_t
        const w = Uint32Array.from({ length: 64 }, () => 0)
        for (let t = 0; t < 16; t++) {
            const i = t * 4
            w[t] = u32((m[i] << 24) | (m[i + 1] << 16) | (m[i + 2] << 8) | m[i + 3])
        }
        for (let t = 16; t < 64; t++) {
            w[t] = u32(lilsig1(w[t - 2]) + w[t - 7] + lilsig0(w[t - 15]) + w[t - 16])
        }
        // Get initial hash value for this block
        let [a, b, c, d, e, f, g, h]: number[] = output
        let t1: number
        let t2: number
        for (let t = 0; t < 64; t++) {
            t1 = u32(h + bigsig1(e) + ch(e, f, g) + K[t] + w[t])
            t2 = u32(bigsig0(a) + maj(a, b, c))
            h = g
            g = f
            f = e
            e = u32(d + t1)
            d = c
            c = b
            b = a
            a = u32(t1 + t2)
        }
        output[0] = u32(output[0] + a)
        output[1] = u32(output[1] + b)
        output[2] = u32(output[2] + c)
        output[3] = u32(output[3] + d)
        output[4] = u32(output[4] + e)
        output[5] = u32(output[5] + f)
        output[6] = u32(output[6] + g)
        output[7] = u32(output[7] + h)
    }

    // Output is a vector of 8*32b words
    // Convert to big-endian 256b/32B bytearray
    const digest = Uint8Array.from({ length: 32 }, () => 0x00)
    for (let o = 0; o < output.length; o++) {
        const word = output[o]
        const d = o * 4
        digest[d] = (word >>> 24) & 0xff
        digest[d + 1] = (word >>> 16) & 0xff
        digest[d + 2] = (word >>> 8) & 0xff
        digest[d + 3] = word & 0xff
    }
    return digest
}

/**
 * Compute the SHA-256 digest of a message
 *
 * @param message Input message bytearray
 * @returns SHA-256 digest bytearray
 */
export function sha256(message: Uint8Array): Uint8Array {
    return compute(parse(pad(message)))
}
