--- passforge/compat.lua
-- Lua 5.1 - 5.4 compatibility layer: 32-bit bitwise operations plus the few
-- portability helpers every other passforge module leans on.
--
-- WHY THIS FILE EXISTS
--   passforge must run on Lua 5.1 (including LuaJIT), 5.2, 5.3 and 5.4 with
--   zero external rocks. The native bitwise operators (&, |, ~, <<, >>) only
--   exist on Lua 5.3+, and integer division (//) only on 5.3+ too. Those
--   tokens can therefore never appear anywhere in this code base: the parser
--   of an older interpreter would reject the whole file even if the operator
--   sat inside a branch that is never taken at runtime.
--
--   All bitwise work goes through the function layer below, which picks the
--   best backend available at load time:
--
--     1. "bit32" - Lua 5.2 standard library
--     2. "bit"   - LuaJIT / LuaBitOp extension (very fast)
--     3. "pure"  - arithmetic fallback that is valid on every 5.x release
--
--   The pure fallback walks the 32 bits with %, / and + on doubles. Every
--   intermediate value stays below 2^53, so IEEE-754 doubles represent all of
--   them exactly and the result is bit-exact on every interpreter.
--
-- CONVENTIONS
--   * Functions accept any number and behave as if the input had been masked
--     to the low 32 bits first (unsigned two's-complement semantics, the same
--     contract bit32 documents).
--   * Shift/rotate counts of 32 or more return 0 (shift) or x (rotate), like
--     bit32; negative counts delegate to the opposite direction.
--   * Everything returns a non-negative number in [0, 2^32).

local M = {}

M.WIDTH = 32
M.MOD   = 4294967296            -- 2^32, modulus for all word arithmetic
M.MASK  = 4294967295            -- 2^32 - 1, all-ones word
M.LN2   = 0.6931471805599453    -- natural log of 2, for log2()

-- ---------------------------------------------------------------------------
-- Backend detection
-- ---------------------------------------------------------------------------

local backend = "pure"

if type(bit32) == "table" and type(bit32.band) == "function" then
  backend = "bit32"
elseif type(bit) == "table" and type(bit.band) == "function" then
  backend = "bit"
end

--- Name of the active bitwise backend: "bit32", "bit" or "pure".
function M.backend()
  return backend
end

-- ---------------------------------------------------------------------------
-- Pure-Lua fallback (always defined; used directly when no library exists)
-- ---------------------------------------------------------------------------

local function pure_band(a, b)
  a = a % M.MOD
  b = b % M.MOD
  local result = 0
  local power = 1
  for _ = 1, M.WIDTH do
    local abit = a % 2
    local bbit = b % 2
    if abit == 1 and bbit == 1 then
      result = result + power
    end
    a = (a - abit) / 2
    b = (b - bbit) / 2
    power = power * 2
  end
  return result
end

local function pure_bor(a, b)
  a = a % M.MOD
  b = b % M.MOD
  local result = 0
  local power = 1
  for _ = 1, M.WIDTH do
    local abit = a % 2
    local bbit = b % 2
    if abit == 1 or bbit == 1 then
      result = result + power
    end
    a = (a - abit) / 2
    b = (b - bbit) / 2
    power = power * 2
  end
  return result
end

local function pure_bxor(a, b)
  a = a % M.MOD
  b = b % M.MOD
  local result = 0
  local power = 1
  for _ = 1, M.WIDTH do
    local abit = a % 2
    local bbit = b % 2
    if abit ~= bbit then
      result = result + power
    end
    a = (a - abit) / 2
    b = (b - bbit) / 2
    power = power * 2
  end
  return result
end

local function pure_bnot(x)
  return M.MASK - (x % M.MOD)
end

local function pure_rshift(x, n)
  x = x % M.MOD
  n = math.floor(tonumber(n) or 0)
  if n == 0 then
    return x
  elseif n < 0 then
    return pure_lshift(x, -n)
  elseif n >= M.WIDTH then
    return 0
  end
  -- Dividing an integer < 2^32 by a power of two is exact in doubles.
  return math.floor(x / 2 ^ n)
end

local function pure_lshift(x, n)
  x = x % M.MOD
  n = math.floor(tonumber(n) or 0)
  if n == 0 then
    return x
  elseif n < 0 then
    return pure_rshift(x, -n)
  elseif n >= M.WIDTH then
    return 0
  end
  -- Keep only the low (32 - n) bits, then move them up. The product is
  -- < 2^32 so the double multiplication is exact.
  return (x % 2 ^ (M.WIDTH - n)) * 2 ^ n
end

local function pure_rrotate(x, n)
  x = x % M.MOD
  n = math.floor(tonumber(n) or 0) % M.WIDTH
  if n == 0 then
    return x
  end
  -- The two halves are disjoint, so addition == OR here.
  return pure_rshift(x, n) + pure_lshift(x, M.WIDTH - n)
end

-- ---------------------------------------------------------------------------
-- Public wrappers (backend selected once, at load time)
-- ---------------------------------------------------------------------------

if backend == "bit32" then
  M.band   = function(a, b) return bit32.band(a, b) end
  M.bor    = function(a, b) return bit32.bor(a, b) end
  M.bxor   = function(a, b) return bit32.bxor(a, b) end
  M.bnot   = function(x) return bit32.bnot(x) end
  M.lshift = function(x, n) return bit32.lshift(x, n) end
  M.rshift = function(x, n) return bit32.rshift(x, n) end
  M.rrotate = function(x, n) return bit32.rrotate(x, n) end
elseif backend == "bit" then
  M.band   = function(a, b) return bit.band(a, b) end
  M.bor    = function(a, b) return bit.bor(a, b) end
  M.bxor   = function(a, b) return bit.bxor(a, b) end
  M.bnot   = function(x) return bit.bnot(x) end
  M.lshift = function(x, n) return bit.lshift(x, n) end
  M.rshift = function(x, n) return bit.rshift(x, n) end
  -- LuaBitOp calls it ror; bit32 calls it rrotate.
  M.rrotate = function(x, n) return bit.ror(x, n) end
else
  M.band    = pure_band
  M.bor     = pure_bor
  M.bxor    = pure_bxor
  M.bnot    = pure_bnot
  M.lshift  = pure_lshift
  M.rshift  = pure_rshift
  M.rrotate = pure_rrotate
end

--- Modular addition of any number of 32-bit words: (a + b + ...) mod 2^32.
-- Each argument is masked first, so the running total stays below
-- 5 * 2^32 < 2^35 and the double sum is exact.
function M.add32(...)
  local count = select("#", ...)
  local total = 0
  for i = 1, count do
    total = total + (select(i, ...) % M.MOD)
  end
  return total % M.MOD
end

--- Base-2 logarithm that works on Lua 5.1 too (math.log there takes no
-- base argument; the base parameter only arrived in Lua 5.2).
function M.log2(x)
  return math.log(x) / M.LN2
end

--- table.unpack on 5.2+, plain unpack on 5.1.
M.unpack = table.unpack or unpack

-- ---------------------------------------------------------------------------
-- Shared error helpers (custom error protocol used across the toolkit)
-- ---------------------------------------------------------------------------

--- Raise a namespaced passforge error. Level 0 keeps the message clean so
-- the CLI can print it verbatim; library users can pattern-match on the
-- "passforge.<module>:" prefix.
function M.fail(module, fmt, ...)
  local msg = string.format(fmt, ...)
  error("passforge." .. tostring(module) .. ": " .. msg, 0)
end

--- Validate that value is an integer inside [lo, hi] and return it floored.
-- lo and hi are optional (pass nil to skip a bound check).
function M.check_int(value, name, lo, hi)
  local n = tonumber(value)
  if not n or math.floor(n) ~= n then
    M.fail("compat", "%s must be an integer, got '%s'", tostring(name), tostring(value))
  end
  n = math.floor(n)
  if lo and n < lo then
    M.fail("compat", "%s must be >= %d, got %d", tostring(name), lo, n)
  end
  if hi and n > hi then
    M.fail("compat", "%s must be <= %d, got %d", tostring(name), hi, n)
  end
  return n
end

--- Validate that value is a non-empty string; return it unchanged.
function M.check_str(value, name)
  if type(value) ~= "string" or #value == 0 then
    M.fail("compat", "%s must be a non-empty string, got '%s'",
           tostring(name), tostring(value))
  end
  return value
end

-- ---------------------------------------------------------------------------
-- Self test - quick known-answer checks for whichever backend was selected.
-- Called by spec/sha256_spec.lua before the FIPS vectors run.
-- ---------------------------------------------------------------------------

function M.selftest()
  assert(M.band(0xF0F0, 0x0FF0) == 0x00F0, "band")
  assert(M.bor(0xF0F0, 0x0F0F) == 0xFFFF, "bor")
  assert(M.bxor(0xFF00, 0x0FF0) == 0xF0F0, "bxor")
  assert(M.bnot(0) == M.MASK, "bnot")
  assert(M.bnot(M.MASK) == 0, "bnot all-ones")
  assert(M.lshift(1, 31) == 0x80000000, "lshift 31")
  assert(M.lshift(1, 32) == 0, "lshift 32")
  assert(M.rshift(0x80000000, 31) == 1, "rshift 31")
  assert(M.rshift(0x80000000, 32) == 0, "rshift 32")
  assert(M.rrotate(0x80000001, 1) == 0xC0000000, "rrotate 1")
  assert(M.rrotate(0x00000001, 4) == 0x10000000, "rrotate 4")
  assert(M.add32(M.MASK, 2) == 1, "add32 wrap")
  assert(M.add32(1, 2, 3, 4) == 10, "add32 variadic")
  assert(M.log2(8) > 2.999 and M.log2(8) < 3.001, "log2")
  return true
end

return M
