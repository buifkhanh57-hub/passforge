--- passforge/sha256.lua
-- SHA-256 implemented from scratch in pure Lua, following FIPS 180-4.
--
-- VERIFICATION
--   The implementation is pinned against the official NIST test vectors and
--   other well-known digests; see spec/sha256_spec.lua:
--
--     ""                          e3b0c44298fc1c149afbf4c8996fb924...
--     "abc"                       ba7816bf8f01cfea414140de5dae2223...
--     "abcdbcde...nopnopq"        248d6a61d20638b8e5c026930c3e6039...
--     "abcdefghbcde...opqrstu"    cf5b16a778af8380036ce59e7b049237...
--     "The quick brown fox..."    d7a8fbb307d7809469ca9abcb0082e4f...
--     "hello world"               b94d27b9934d3e08a52e52d7da7dabfa...
--     "a" x 1,000,000             cdc76e5c9914fb9281a1c7e284d73e67...
--
-- DESIGN
--   * All arithmetic goes through passforge.compat (bit32 / LuaJIT bit /
--     pure-Lua fallback), so the file runs unchanged on Lua 5.1 - 5.4.
--   * Words are stored as numbers in [0, 2^32); every operation stays exact
--     in IEEE-754 doubles.
--   * The hashing core is incremental: new() -> update() -> finish(), which
--     lets digest_file() stream large files in fixed 64 KiB chunks instead of
--     loading them whole.
--
-- SPEED HONESTY
--   Pure Lua is not fast. Expect roughly 20-200 KB/s depending on interpreter
--   and backend (LuaJIT with the bit library is the top of that range, plain
--   5.1 with the pure arithmetic fallback the bottom). For password-sized
--   inputs this is irrelevant; for multi-megabyte files use a native tool.

local compat = require("passforge.compat")

local M = {}

local band    = compat.band
local bxor    = compat.bxor
local bnot    = compat.bnot
local rshift  = compat.rshift
local rrotate = compat.rrotate
local add32   = compat.add32

M.BLOCK_SIZE  = 64   -- bytes per compression block (512 bits)
M.DIGEST_SIZE = 32   -- bytes per digest (256 bits)

-- ---------------------------------------------------------------------------
-- FIPS 180-4 section 4.2.2: first 64 primes p, K[i] = frac(p^(1/3)) * 2^32
-- ---------------------------------------------------------------------------

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

-- FIPS 180-4 section 5.3.3: initial hash value, first 32 bits of the
-- fractional parts of the square roots of the first 8 primes.
local function fresh_h()
  return {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  }
end

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

--- Encode a 32-bit word as 4 bytes, big-endian.
local function u32be(x)
  x = x % compat.MOD
  return string.char(
    math.floor(x / 16777216) % 256,
    math.floor(x / 65536) % 256,
    math.floor(x / 256) % 256,
    x % 256
  )
end

--- Render a binary string as lowercase hex.
local function tohex(raw)
  if type(raw) ~= "string" then
    compat.fail("sha256", "tohex expects a binary string, got %s", type(raw))
  end
  return (raw:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end

-- ---------------------------------------------------------------------------
-- Compression function (FIPS 180-4 section 6.2.2)
-- ---------------------------------------------------------------------------

local function compress(H, block)
  -- 1. Message schedule: 16 words from the block, then 48 mixed words.
  local w = {}
  for i = 1, 16 do
    local j = (i - 1) * 4
    w[i] = block:byte(j + 1) * 16777216
         + block:byte(j + 2) * 65536
         + block:byte(j + 3) * 256
         + block:byte(j + 4)
  end
  for t = 17, 64 do
    local a15 = w[t - 15]
    local a2 = w[t - 2]
    -- sigma0: ROTR7 ^ ROTR18 ^ SHR3
    local s0 = bxor(rrotate(a15, 7), bxor(rrotate(a15, 18), rshift(a15, 3)))
    -- sigma1: ROTR17 ^ ROTR19 ^ SHR10
    local s1 = bxor(rrotate(a2, 17), bxor(rrotate(a2, 19), rshift(a2, 10)))
    w[t] = add32(w[t - 16], s0, w[t - 7], s1)
  end

  -- 2. Sixty-four rounds of mixing over the working registers.
  local a, b, c, d = H[1], H[2], H[3], H[4]
  local e, f, g, h = H[5], H[6], H[7], H[8]
  for t = 1, 64 do
    -- uppercase Sigma1 / choose
    local S1 = bxor(rrotate(e, 6), bxor(rrotate(e, 11), rrotate(e, 25)))
    local ch = bxor(band(e, f), band(bnot(e), g))
    local temp1 = add32(h, S1, K[t], w[t])
    -- uppercase Sigma0 / majority
    local S0 = bxor(rrotate(a, 2), bxor(rrotate(a, 13), rrotate(a, 22)))
    local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
    local temp2 = add32(S0, maj)

    h = g
    g = f
    f = e
    e = add32(d, temp1)
    d = c
    c = b
    b = a
    a = add32(temp1, temp2)
  end

  -- 3. Feed the working variables back into the chaining value.
  H[1] = add32(H[1], a)
  H[2] = add32(H[2], b)
  H[3] = add32(H[3], c)
  H[4] = add32(H[4], d)
  H[5] = add32(H[5], e)
  H[6] = add32(H[6], f)
  H[7] = add32(H[7], g)
  H[8] = add32(H[8], h)
end

-- ---------------------------------------------------------------------------
-- Incremental API: new() -> update(state, data) -> finish(state)
-- ---------------------------------------------------------------------------

--- Create an empty hashing state.
function M.new()
  return { h = fresh_h(), buf = "", len = 0 }
end

--- Feed more data into the state. Accepts any number of calls between
-- new() and finish(); the internal buffer keeps the trailing partial block.
function M.update(st, data)
  if type(st) ~= "table" or type(st.h) ~= "table" then
    compat.fail("sha256", "update expects a state from sha256.new()")
  end
  if type(data) ~= "string" or #data == 0 then
    return st
  end
  st.len = st.len + #data
  local buf = st.buf .. data
  local full = #buf - (#buf % M.BLOCK_SIZE)
  for off = 1, full, M.BLOCK_SIZE do
    compress(st.h, buf:sub(off, off + M.BLOCK_SIZE - 1))
  end
  st.buf = buf:sub(full + 1)
  return st
end

--- Close the state and return the 32-byte raw digest. The state must not be
-- updated after finish() - create a new one instead.
function M.finish(st)
  if type(st) ~= "table" or type(st.h) ~= "table" then
    compat.fail("sha256", "finish expects a state from sha256.new()")
  end
  -- FIPS padding: 0x80, then zeros up to 56 mod 64, then the 64-bit
  -- big-endian message length in bits. The message length here is measured
  -- BEFORE this synthetic padding is fed in, so compute the pad first.
  local bit_len = st.len * 8
  local hi = math.floor(bit_len / compat.MOD)
  local lo = bit_len % compat.MOD
  local pad = "\128" .. string.rep("\0", (55 - st.len) % 64) .. u32be(hi) .. u32be(lo)
  M.update(st, pad)

  local out = {}
  for i = 1, 8 do
    out[i] = u32be(st.h[i])
  end
  return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- One-shot API
-- ---------------------------------------------------------------------------

--- Raw 32-byte digest of a string.
function M.digest(message)
  local st = M.new()
  M.update(st, compat.check_str(message, "message"))
  return M.finish(st)
end

--- Lowercase hex digest of a string (the form everyone compares).
function M.hex(message)
  return tohex(M.digest(message))
end

-- Kept as a friendly alias; "hexdigest" reads better from other languages.
M.hexdigest = M.hex

--- Raw digest of a file, streamed in 64 KiB chunks.
function M.digest_file(path)
  local fh, open_err = io.open(path, "rb")
  if not fh then
    compat.fail("sha256", "cannot open file '%s': %s", tostring(path), tostring(open_err))
  end
  local st = M.new()
  while true do
    local chunk = fh:read(65536)
    if not chunk then break end
    M.update(st, chunk)
  end
  fh:close()
  return M.finish(st)
end

--- Lowercase hex digest of a file.
function M.hexdigest_file(path)
  return tohex(M.digest_file(path))
end

M.tohex = tohex

--- Number of constants in the K table (exposed so specs can sanity-check).
function M.k_count()
  return #K
end

return M
