--- passforge/passphrase.lua
-- Passphrase generation from the embedded 512-word list.
--
-- ENTROPY MODEL
--   With a 512-word list, each word contributes exactly log2(512) = 9.00
--   bits (wordlist.bits_per_word() computes this dynamically, so a future
--   list expansion stays correct). An appended digit adds log2(10) ~ 3.32
--   bits. Capitalization adds nothing (it is deterministic given the word),
--   and neither does the separator - both are documented cosmetic options.
--
-- COMBINATIONS
--   combinations = list_size ^ words (optionally * 10 with append_digit).
--   Returned as a formatted string because 512^12 already overflows the
--   reader's patience, though not IEEE-754 doubles (512^12 ~ 1.3e106).

local compat   = require("passforge.compat")
local random   = require("passforge.random")
local wordlist = require("passforge.wordlist")

local M = {}

local DEFAULT_WORDS = 4
local MIN_WORDS = 3
local MAX_WORDS = 24

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

local function check_word_count(n)
  return compat.check_int(n, "words", MIN_WORDS, MAX_WORDS)
end

--- Validate separator: 1..3 printable ASCII characters, no whitespace.
local function check_separator(sep)
  if type(sep) ~= "string" or #sep < 1 or #sep > 3 then
    compat.fail("passphrase", "separator must be a string of 1-3 characters, got '%s'",
      tostring(sep))
  end
  if sep:find("%s") then
    compat.fail("passphrase", "separator must not contain whitespace")
  end
  return sep
end

local function resolve_rng(opts)
  local rng = opts.rng
  if rng == nil then
    return random.default()
  end
  if type(rng) ~= "table" or type(rng.below) ~= "function" then
    compat.fail("passphrase", "opts.rng must be a passforge.random generator")
  end
  return rng
end

--- Capitalize helper: first character upper, remainder untouched.
local function capitalize(word)
  return word:sub(1, 1):upper() .. word:sub(2)
end

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

--- Build one passphrase. Options:
--   words        integer 3..24 (default 4)
--   separator    1-3 chars (default "-")
--   capitalize   boolean, first letter of every word (default false)
--   append_digit boolean, one trailing random digit (default false)
--   rng          injectable passforge.random generator
function M.build(opts)
  opts = opts or {}
  local wc = check_word_count(opts.words or DEFAULT_WORDS)
  local sep = check_separator(opts.separator or "-")
  local rng = resolve_rng(opts)
  local do_capitalize = opts.capitalize and true or false
  local do_digit = opts.append_digit and true or false

  local parts = {}
  for i = 1, wc do
    local word = wordlist.pick(rng)
    if do_capitalize then
      word = capitalize(word)
    end
    parts[i] = word
  end

  local phrase = table.concat(parts, sep)
  if do_digit then
    -- string.format + floor keeps Lua 5.3/5.4 from rendering "3.0".
    phrase = phrase .. string.format("%d", rng:below(10))
  end
  return phrase
end

--- generate() is the semantic alias used by the CLI and library users.
M.generate = M.build

--- Generate `opts.count` distinct passphrases (dedup with retry cap).
function M.generate_many(opts)
  opts = opts or {}
  local count = compat.check_int(opts.count or 1, "count", 1, 1000)
  local out = {}
  local seen = {}
  local tries = 0
  local max_tries = count * 64 + 64
  while #out < count do
    tries = tries + 1
    if tries > max_tries then
      compat.fail("passphrase",
        "could not produce %d distinct passphrases (word count too small?)", count)
    end
    local phrase = M.build(opts)
    if not seen[phrase] then
      seen[phrase] = true
      out[#out + 1] = phrase
    end
  end
  return out
end

--- Exact entropy estimate in bits for the given options.
function M.entropy_bits(opts)
  opts = opts or {}
  local wc = check_word_count(opts.words or DEFAULT_WORDS)
  local bits = wc * wordlist.bits_per_word()
  if opts.append_digit then
    bits = bits + compat.log2(10)
  end
  return bits
end

--- Number of distinct passphrases as a human string, e.g. "1.31e+106".
function M.combinations(opts)
  opts = opts or {}
  local wc = check_word_count(opts.words or DEFAULT_WORDS)
  local space = #wordlist.all() ^ wc
  if opts.append_digit then
    space = space * 10
  end
  return string.format("%.3e", space)
end

--- Structured explanation of an option set (used by `pass --json` and docs).
function M.explain(opts)
  opts = opts or {}
  local wc = check_word_count(opts.words or DEFAULT_WORDS)
  return {
    words = wc,
    wordlist_size = wordlist.count(),
    bits_per_word = math.floor(wordlist.bits_per_word() * 100 + 0.5) / 100,
    separator = opts.separator or "-",
    capitalize = opts.capitalize and true or false,
    append_digit = opts.append_digit and true or false,
    entropy_bits = math.floor(M.entropy_bits(opts) * 100 + 0.5) / 100,
    combinations = M.combinations(opts),
  }
end

--- Tuning constants, exported for the CLI help and the tests.
M.LIMITS = {
  default_words = DEFAULT_WORDS,
  min_words = MIN_WORDS,
  max_words = MAX_WORDS,
}

return M
