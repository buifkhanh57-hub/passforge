--- passforge/random.lua
-- Random source for passforge: seed collection, a 32-bit xorshift128
-- generator, and unbiased sampling helpers built on top of it.
--
-- HONEST SECURITY NOTES (see README "Security notes" for the long version)
--   * When /dev/urandom can be read (POSIX, io.popen enabled) its bytes are
--     hashed into the seed. That is decent seeding.
--   * When it cannot (restricted sandbox, Windows, disabled io.popen) the
--     seed comes from os.time + os.clock + collectgarbage counters + fresh
--     table addresses. That is weak: an attacker who knows roughly WHEN a
--     password was generated can enumerate the small seed space.
--   * The output stream itself is xorshift128 (Marsaglia 2003): period
--     2^128 - 1, fast, decent statistical quality - but NOT a CSPRNG. This
--     is a deliberate trade-off for a pure-Lua, dependency-free toolkit.
--
-- DETERMINISTIC MODE
--   M.new(seed) with a non-empty seed string derives the state purely from
--   sha256("passforge-seed" .. seed), skipping entropy collection entirely.
--   Two generators built from the same seed emit identical streams. Useful
--   for tests and for reproducing bug reports - and flagged as UNSAFE for
--   real passwords in the CLI help.

local compat = require("passforge.compat")
local sha256 = require("passforge.sha256")

local M = {}

local RNG = {}
RNG.__index = RNG

local TWO32 = compat.MOD

M.ENGINE = "xorshift128 (32-bit, sha256-seeded)"

local entropy_counter = 0

-- ---------------------------------------------------------------------------
-- Seeding
-- ---------------------------------------------------------------------------

--- Try to read nbytes from /dev/urandom via io.popen.
-- Returns ok(boolean), data(string|nil). Every step is guarded: io.popen may
-- be disabled entirely, the popen call itself may fail, and on Windows we do
-- not even try (no /dev/urandom there).
local function read_urandom(nbytes)
  if not io or not io.popen then
    return false, nil
  end
  if package.config:sub(1, 1) == "\\" then
    return false, nil
  end
  local ok, fh = pcall(io.popen,
    "head -c " .. tostring(nbytes) .. " /dev/urandom 2>/dev/null")
  if not ok or not fh then
    return false, nil
  end
  local ok2, data = pcall(function() return fh:read("*a") end)
  pcall(function() fh:close() end)
  if not ok2 or type(data) ~= "string" or #data == 0 then
    return false, nil
  end
  return true, data
end

--- Collect whatever weak entropy the environment offers and concatenate it.
-- The exact composition does not matter for correctness (sha256 compresses
-- it to a uniform-looking state) - more variety is simply better mixing.
local function gather_entropy()
  entropy_counter = entropy_counter + 1
  local parts = {}

  parts[#parts + 1] = "time=" .. tostring(os.time())
  -- %.17g keeps every bit of os.clock()'s fractional part.
  parts[#parts + 1] = "clock=" .. string.format("%.17g", os.clock())
  parts[#parts + 1] = "gc=" .. tostring(math.floor(collectgarbage("count") or 0))
  parts[#parts + 1] = "n=" .. tostring(entropy_counter)

  -- The address of a freshly allocated table differs on every call in most
  -- interpreters (tostring renders the pointer). Cheap ASLR-ish stir.
  local probe = {}
  local addr = tostring(probe):match("0x%x+")
  parts[#parts + 1] = "addr=" .. (addr or "na")

  local ok, data = read_urandom(32)
  if ok and data then
    -- Raw bytes concatenated are fine: Lua strings are 8-bit clean and
    -- sha256 accepts any binary material.
    parts[#parts + 1] = "urandom=" .. data
  else
    parts[#parts + 1] = "urandom=unavailable"
  end

  return table.concat(parts, "|")
end

--- Turn 32 hex chars (one sha256 digest) into four 32-bit state words.
local function words_from_hex(hex)
  local words = {}
  for i = 0, 3 do
    local chunk = hex:sub(i * 8 + 1, i * 8 + 8)
    words[i + 1] = tonumber(chunk, 16) or 0
  end
  return words
end

-- ---------------------------------------------------------------------------
-- RNG object
-- ---------------------------------------------------------------------------

--- Core xorshift128 step (Marsaglia 2003). Returns an unbiased-enough
-- 32-bit word; period is 2^128 - 1 over the 4-word state.
function RNG:next_u32()
  local s = self.state
  local x = s[1]
  local t = compat.bxor(x, compat.lshift(x, 11))
  s[1] = s[2]
  s[2] = s[3]
  s[3] = s[4]
  local w = s[4]
  s[4] = compat.bxor(compat.bxor(w, compat.rshift(w, 19)),
                     compat.bxor(t, compat.rshift(t, 8)))
  self.n = self.n + 1
  return s[4]
end

--- Uniform integer in [0, n-1] via rejection sampling: draws above the
-- largest multiple of n are discarded, which removes the modulo bias that
-- a naive "word % n" would introduce (biases are tiny for small n but
-- real: e.g. word % 10 under-represents 7 of 10 values by ~1.5e-8).
function RNG:below(n)
  n = compat.check_int(n, "n", 1, TWO32 - 1)
  if n == 1 then
    return 0
  end
  local limit = TWO32 - (TWO32 % n)
  local x = self:next_u32()
  while x >= limit do
    x = self:next_u32()
  end
  return x % n
end

--- Uniform integer in [lo, hi], both bounds included.
function RNG:range(lo, hi)
  lo = compat.check_int(lo, "lo")
  hi = compat.check_int(hi, "hi")
  if lo > hi then
    compat.fail("random", "range lo (%d) must be <= hi (%d)", lo, hi)
  end
  return lo + self:below(hi - lo + 1)
end

--- Uniform random element of a non-empty array-like table.
function RNG:pick(t)
  local n = #t
  if n == 0 then
    compat.fail("random", "cannot pick from an empty table")
  end
  return t[self:below(n) + 1]
end

--- Fisher-Yates shuffle, in place; returns t for chaining.
function RNG:shuffle(t)
  local n = #t
  for i = n, 2, -1 do
    local j = self:below(i) + 1
    t[i], t[j] = t[j], t[i]
  end
  return t
end

--- k distinct random elements of t (partial Fisher-Yates on a copy).
function RNG:sample(t, k)
  local n = #t
  k = compat.check_int(k, "k", 0, n)
  local copy = {}
  for i = 1, n do
    copy[i] = t[i]
  end
  for i = 1, k do
    local j = i + self:below(n - i + 1)
    copy[i], copy[j] = copy[j], copy[i]
  end
  local out = {}
  for i = 1, k do
    out[i] = copy[i]
  end
  return out
end

--- n random bytes as a Lua string (8-bit clean, may contain NULs).
function RNG:bytes(nbytes)
  nbytes = compat.check_int(nbytes, "nbytes", 1, 65536)
  local out = {}
  for i = 1, nbytes do
    -- math.floor keeps Lua 5.3/5.4 happy: string.char wants an integer.
    out[i] = string.char(math.floor(self:below(256)))
  end
  return table.concat(out)
end

--- n random hex characters (n may be odd; the last nibble is simply cut).
function RNG:hex(nchars)
  nchars = compat.check_int(nchars, "nchars", 1, 4096)
  local raw = self:bytes(math.ceil(nchars / 2))
  local out = {}
  for i = 1, #raw do
    out[i] = string.format("%02x", raw:byte(i))
  end
  return (table.concat(out):sub(1, nchars))
end

--- True with probability p in [0, 1] (quantised to one part in a million).
function RNG:chance(p)
  p = tonumber(p)
  if not p or p < 0 or p > 1 then
    compat.fail("random", "chance expects a probability in [0, 1], got '%s'", tostring(p))
  end
  return self:below(1000000) < math.floor(p * 1000000 + 0.5)
end

--- Number of next_u32() draws consumed so far (diagnostics / bench).
function RNG:draws()
  return self.n
end

--- Re-mix the state with fresh environment entropy plus any extra string.
-- Deliberately NOT deterministic: calling stir() breaks reproducibility.
function RNG:stir(extra)
  local material = gather_entropy() .. "|draws=" .. tostring(self.n)
  if type(extra) == "string" and #extra > 0 then
    material = material .. "|extra=" .. extra
  end
  self.state = words_from_hex(sha256.hex(material))
  -- Warm-up: 8 discarded draws remove any residual seed structure.
  for _ = 1, 8 do
    self:next_u32()
  end
end

-- ---------------------------------------------------------------------------
-- Constructor
-- ---------------------------------------------------------------------------

--- Build a generator. With seed_material (non-empty string) the state is
-- deterministic (tests, reproduction). Without one, environment entropy
-- (ideally /dev/urandom) seeds the state.
function M.new(seed_material)
  local hex
  if type(seed_material) == "string" and #seed_material > 0 then
    hex = sha256.hex("passforge-seed|" .. seed_material)
  else
    hex = sha256.hex(gather_entropy())
  end
  local state = words_from_hex(hex)
  -- xorshift128 is degenerate on the all-zero state; the probability of
  -- hitting it is 2^-128, but guard anyway because it costs nothing.
  if state[1] == 0 and state[2] == 0 and state[3] == 0 and state[4] == 0 then
    state[1] = 0x9e3779b9
    state[2] = 0x7f4a7c15
    state[3] = 0x94d049bb
    state[4] = 0x133111eb
  end
  local self = setmetatable({ state = state, n = 0 }, RNG)
  for _ = 1, 8 do
    self:next_u32()
  end
  return self
end

-- ---------------------------------------------------------------------------
-- Module-level singleton: passforge.random.uint32() and friends operate on
-- one shared generator, while M.new() builds isolated ones.
-- ---------------------------------------------------------------------------

local default_rng = M.new()

function M.default()
  return default_rng
end

function M.uint32()
  return default_rng:next_u32()
end

function M.below(n)
  return default_rng:below(n)
end

function M.range(lo, hi)
  return default_rng:range(lo, hi)
end

function M.pick(t)
  return default_rng:pick(t)
end

function M.shuffle(t)
  return default_rng:shuffle(t)
end

function M.sample(t, k)
  return default_rng:sample(t, k)
end

function M.bytes(n)
  return default_rng:bytes(n)
end

function M.hex(n)
  return default_rng:hex(n)
end

function M.chance(p)
  return default_rng:chance(p)
end

return M
