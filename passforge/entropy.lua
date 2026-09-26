--- passforge/entropy.lua
-- Entropy mathematics shared by every passforge component.
--
-- WHAT LIVES HERE
--   * pool arithmetic: bits = length * log2(pool_size), the classic
--     independent-draws model;
--   * string-side estimators (Shannon content, distinct-alphabet bound);
--   * the single SCALE table that maps bits -> score(0..5) -> verdict label,
--     used by strength.lua, audit.lua and the CLI so numbers can never
--     disagree between commands;
--   * crack-time modelling over a table of attacker guess rates, with
--     honest documentation of what each rate assumes;
--   * per-mode estimates for the two generation modes (random "gen" and
--     word-based "pass") that the CLI exposes via `passforge entropy`.
--
-- HONESTY NOTES (expanded in the README)
--   Entropy here is a property of the GENERATION PROCESS, not of one string.
--   For a password you did not generate yourself the numbers below are an
--   upper bound: pattern detectors (strength.lua) subtract from them. All
--   crack times are AVERAGE case (half the keyspace) and assume the attacker
--   knows the generation scheme - the standard conservative assumption.

local compat    = require("passforge.compat")
local charsets  = require("passforge.charsets")
local generator = require("passforge.generator")
local passphrase = require("passforge.passphrase")
local wordlist  = require("passforge.wordlist")

local M = {}

-- ---------------------------------------------------------------------------
-- The shared verdict scale
-- ---------------------------------------------------------------------------

-- Score thresholds in bits. First entry whose min_bits <= bits wins, so the
-- table MUST stay ordered from lowest to highest min_bits.
M.SCALE = {
  { min_bits = 0,   score = 0, label = "very weak" },
  { min_bits = 28,  score = 1, label = "weak" },
  { min_bits = 36,  score = 2, label = "fair" },
  { min_bits = 60,  score = 3, label = "strong" },
  { min_bits = 80,  score = 4, label = "very strong" },
  { min_bits = 100, score = 5, label = "excellent" },
}

--- Map an entropy figure to { score = 0..5, label = string }.
-- Negative bits (pattern penalties can overshoot) clamp to score 0.
function M.scale_for(bits)
  bits = tonumber(bits) or 0
  local chosen = M.SCALE[1]
  for i = 1, #M.SCALE do
    local rung = M.SCALE[i]
    if bits >= rung.min_bits then
      chosen = rung
    end
  end
  return { score = chosen.score, label = chosen.label }
end

--- Score-only convenience wrapper.
function M.score_for(bits)
  return M.scale_for(bits).score
end

--- Label-only convenience wrapper.
function M.label_for(bits)
  return M.scale_for(bits).label
end

--- Round to two decimals without %.2f (keeps numbers JSON-friendly).
function M.round2(x)
  x = tonumber(x) or 0
  local scaled = x * 100
  local rounded = math.floor(scaled + 0.5)
  if x < 0 then
    rounded = math.ceil(scaled - 0.5)
  end
  return rounded / 100
end

--- Formatted bits string, e.g. "41.70 bits".
function M.format_bits(bits)
  return string.format("%.2f bits", tonumber(bits) or 0)
end

-- ---------------------------------------------------------------------------
-- Pool-side estimators (generation-process view)
-- ---------------------------------------------------------------------------

--- Classic brute-force entropy: length independent draws from a pool.
function M.bits_from_pool(pool_size, length)
  pool_size = compat.check_int(pool_size, "pool_size", 0)
  length = compat.check_int(length, "length", 0)
  if pool_size < 2 or length == 0 then
    return 0
  end
  return length * compat.log2(pool_size)
end

--- Number of distinct characters present in s (0 for the empty string).
function M.distinct_chars(s)
  compat.check_str(s, "s")
  local seen = {}
  local distinct = 0
  for i = 1, #s do
    local ch = s:sub(i, i)
    if not seen[ch] then
      seen[ch] = true
      distinct = distinct + 1
    end
  end
  return distinct
end

--- Pool size attributed to an observed password: sum of the alphabet sizes
-- of every character class it touches (charsets.CLASS_SIZE). This is the
-- same pool model the generator uses, which keeps both sides consistent.
function M.pool_for_password(s)
  compat.check_str(s, "s")
  return charsets.pool_size_for(s)
end

--- Brute-force view of an observed password: pool_for_password ^ length.
function M.bits_for_password(s)
  compat.check_str(s, "s")
  if #s == 0 then
    return 0
  end
  return M.bits_from_pool(M.pool_for_password(s), #s)
end

--- Alphabet-limited view: length * log2(distinct chars actually used).
-- A 20-character password of only "aaaa" has distinct=1 -> 0 real entropy
-- beyond the choice to repeat; this bound catches that, the pool view does
-- not. Returns 0 for the empty string and for single-character strings
-- (where the bound would claim log2(1)=0 anyway).
function M.unique_bits(s)
  compat.check_str(s, "s")
  local distinct = M.distinct_chars(s)
  if distinct < 2 then
    return 0
  end
  return #s * compat.log2(distinct)
end

--- Empirical Shannon content: H = -sum p_i * log2(p_i) per position,
-- multiplied by the length. Measures redundancy INSIDE the string ("abcd"
-- scores high, "aaaa" scores 0) - it is NOT a security estimate by itself,
-- but it is the fastest way to expose repeated structure to humans.
function M.shannon_bits(s)
  compat.check_str(s, "s")
  local n = #s
  if n == 0 then
    return 0
  end
  local counts = {}
  for i = 1, n do
    local ch = s:sub(i, i)
    counts[ch] = (counts[ch] or 0) + 1
  end
  local h = 0
  for _, c in pairs(counts) do
    local p = c / n
    h = h - p * compat.log2(p)
  end
  return h * n
end

--- The number the analyzer reports: the smallest of the pool view, the
-- distinct-alphabet view and the Shannon view (never below 0). Taking the
-- minimum is deliberately pessimistic - each view is an upper bound from a
-- different attack model, so the strongest bound is the honest one.
function M.effective_bits(s)
  compat.check_str(s, "s")
  if #s == 0 then
    return 0
  end
  local a = M.bits_for_password(s)
  local b = M.unique_bits(s)
  local c = M.shannon_bits(s)
  local best = a
  if b < best then
    best = b
  end
  if c < best then
    best = c
  end
  if best < 0 then
    best = 0
  end
  return best
end

-- ---------------------------------------------------------------------------
-- Crack-time modelling
-- ---------------------------------------------------------------------------

-- Ordered weakest -> strongest adversary. Rates are order-of-magnitude
-- figures documented in the README; do not present them as measurements.
M.GUESS_RATES = {
  { id = "online_throttled", label = "online, rate-limited (100/s)",
    rate = 100 },
  { id = "online_fast",      label = "online, unthrottled (10^4/s)",
    rate = 10000 },
  { id = "offline_slow",     label = "offline, slow hash (10^5/s)",
    rate = 100000 },
  { id = "offline_fast",     label = "offline, fast hash (10^11/s)",
    rate = 100000000000 },
  { id = "offline_farm",     label = "offline, GPU farm (10^15/s)",
    rate = 1000000000000000 },
}

--- Total guesses to exhaust the keyspace for `bits` of entropy: 2^bits.
-- Doubles represent this exactly enough up to ~1e300; beyond a few hundred
-- bits the figure is "astronomical" anyway and stays finite in IEEE-754.
function M.guesses(bits)
  bits = tonumber(bits) or 0
  if bits <= 0 then
    return 1
  end
  if bits > 1000 then
    bits = 1000                      -- 2^1000 ~ 1.07e301, past this just cap
  end
  return 2 ^ bits
end

--- Average crack time in seconds: half the keyspace divided by the rate.
function M.crack_seconds(bits, rate)
  rate = tonumber(rate) or 0
  if rate <= 0 then
    compat.fail("entropy", "crack rate must be > 0, got '%s'", tostring(rate))
  end
  return M.guesses(bits) / 2 / rate
end

--- Human rendering of a duration. Units:
--   < 1s        "instant"
--   < 60s       seconds
--   < 1 hour    minutes
--   < 1 day     hours
--   < 1 month   days        (month = 30.44 days, i.e. 2,629,746 s)
--   < 1 year    months      (year  = 365.24 days, i.e. 31,556,952 s)
--   < 100 years years
--   < 1e9 years "N centuries" (a century = 100 years)
--   else        scientific notation of years
function M.human_time(seconds)
  seconds = tonumber(seconds) or 0
  if seconds < 1 then
    return "instant"
  end
  if seconds < 60 then
    return string.format("%.0f seconds", seconds)
  end
  if seconds < 3600 then
    return string.format("%.0f minutes", seconds / 60)
  end
  if seconds < 86400 then
    return string.format("%.0f hours", seconds / 3600)
  end
  if seconds < 2629746 then
    return string.format("%.0f days", seconds / 86400)
  end
  if seconds < 31556952 then
    return string.format("%.0f months", seconds / 2629746)
  end
  local years = seconds / 31556952
  if years < 100 then
    return string.format("%.0f years", years)
  end
  if years < 1000000000 then
    local centuries = years / 100
    if centuries < 10 then
      return string.format("%.1f centuries", centuries)
    end
    return string.format("%.0f centuries", centuries)
  end
  return string.format("%.2e years", years)
end

--- Crack-time table for every documented rate: array of
-- { id, label, rate, seconds, human }. Used verbatim by reports and --json.
function M.crack_table(bits)
  local out = {}
  for i = 1, #M.GUESS_RATES do
    local entry = M.GUESS_RATES[i]
    local seconds = M.crack_seconds(bits, entry.rate)
    out[i] = {
      id = entry.id,
      label = entry.label,
      rate = entry.rate,
      seconds = seconds,
      human = M.human_time(seconds),
    }
  end
  return out
end

-- ---------------------------------------------------------------------------
-- Per-mode estimates (what `passforge entropy` shows)
-- ---------------------------------------------------------------------------

--- Structured estimate for the random-generator mode. Accepts exactly the
-- same options as generator.generate() (length, sets, exclude_ambiguous...).
function M.estimate_generate(opts)
  opts = opts or {}
  local length = opts.length or generator.LIMITS.default_length
  local pool = generator.pool_size(opts)
  local bits = generator.entropy_bits(opts)
  local verdict = M.scale_for(bits)
  return {
    mode = "gen",
    length = length,
    pool_size = pool,
    bits_per_guess = M.round2(compat.log2(pool)),
    entropy_bits = M.round2(bits),
    combinations = string.format("%.3e", M.guesses(bits)),
    score = verdict.score,
    verdict = verdict.label,
    crack = M.crack_table(bits),
    description = generator.describe(opts),
  }
end

--- Structured estimate for the passphrase mode. Accepts the same options as
-- passphrase.build() (words, separator, capitalize, append_digit).
function M.estimate_passphrase(opts)
  opts = opts or {}
  local words = opts.words or passphrase.LIMITS.default_words
  local bits = passphrase.entropy_bits(opts)
  local verdict = M.scale_for(bits)
  return {
    mode = "pass",
    words = words,
    wordlist_size = wordlist.count(),
    bits_per_word = M.round2(wordlist.bits_per_word()),
    entropy_bits = M.round2(bits),
    combinations = passphrase.combinations(opts),
    score = verdict.score,
    verdict = verdict.label,
    crack = M.crack_table(bits),
    capitalize = opts.capitalize and true or false,
    append_digit = opts.append_digit and true or false,
  }
end

--- Combined pool-size reference table for help output and tests: returns
-- { lower=26, upper=26, digits=10, symbols=32, other=64 } plus the common
-- combined totals (62 for letters+digits, 94 for everything).
function M.pool_reference()
  local ref = {}
  for name, size in pairs(charsets.CLASS_SIZE) do
    ref[name] = size
  end
  ref.lower_upper = 52
  ref.lower_upper_digits = 62
  ref.all_printable = 94
  return ref
end

--- Quick sanity check used by the spec suite.
function M.selftest()
  assert(M.bits_from_pool(26, 8) > 37.6 and M.bits_from_pool(26, 8) < 37.7,
    "bits_from_pool 26^8")
  assert(M.bits_from_pool(62, 16) > 95.2 and M.bits_from_pool(62, 16) < 95.3,
    "bits_from_pool 62^16")
  assert(M.bits_from_pool(10, 0) == 0, "zero length")
  assert(M.scale_for(10).score == 0, "scale very weak")
  assert(M.scale_for(30).score == 1, "scale weak")
  assert(M.scale_for(40).score == 2, "scale fair")
  assert(M.scale_for(70).score == 3, "scale strong")
  assert(M.scale_for(90).score == 4, "scale very strong")
  assert(M.scale_for(120).score == 5, "scale excellent")
  assert(M.scale_for(-5).score == 0, "negative clamps to 0")
  assert(M.guesses(0) == 1, "guesses 0")
  assert(M.guesses(1) == 2, "guesses 1")
  assert(M.crack_seconds(1, 1) == 1, "2^1 guesses / 2 average / rate 1")
  assert(M.distinct_chars("aabbcc") == 3, "distinct")
  assert(M.shannon_bits("aaaa") == 0, "shannon of constant string")
  assert(M.human_time(0.5) == "instant", "human instant")
  assert(M.human_time(30) == "30 seconds", "human seconds")
  return true
end

return M
