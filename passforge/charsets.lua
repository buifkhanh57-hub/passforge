--- passforge/charsets.lua
-- Character sets, ambiguity filtering and per-character classification.
--
-- This module is the single place that knows WHAT a character class contains.
-- The generator builds pools from it, the strength analyzer classifies
-- passwords with it, and the CLI help quotes its sizes. Keep every constant
-- here so the three consumers can never drift apart.

local compat = require("passforge.compat")

local M = {}

-- ---------------------------------------------------------------------------
-- The four canonical sets
-- ---------------------------------------------------------------------------

M.SETS = {
  -- 26 lowercase ASCII letters
  lower   = "abcdefghijklmnopqrstuvwxyz",
  -- 26 uppercase ASCII letters
  upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  -- 10 digits
  digits  = "0123456789",
  -- 32 printable ASCII symbols (no space, no backslash)
  symbols = "!@#$%^&*()-_=+[]{};:,.<>?/|`~'\"",
}

-- Canonical order used everywhere (reports, CLI help, pool building).
local SET_ORDER = { "lower", "upper", "digits", "symbols" }

--- Effective alphabet size per class, used by entropy estimation.
-- "other" covers space and extended bytes; 64 is a deliberately rough but
-- conservative-ish middle ground documented in the README.
M.CLASS_SIZE = { lower = 26, upper = 26, digits = 10, symbols = 32, other = 64 }

-- Characters that are easy to misread in most UI fonts. Excluding them
-- shrinks each set a little (see ambiguous_counts()) but prevents the
-- classic "was that an l or a 1?" support ticket.
M.AMBIGUOUS = "Il1O0o|"

-- Short aliases accepted by --sets and by resolve_sets().
M.ALIASES = { l = "lower", u = "upper", d = "digits", s = "symbols" }

-- ---------------------------------------------------------------------------
-- Ambiguity helpers
-- ---------------------------------------------------------------------------

local AMBIGUOUS_CLASS = "[" .. M.AMBIGUOUS .. "]"

--- Return a copy of s with every ambiguous character removed.
function M.remove_ambiguous(s)
  compat.check_str(s, "s")
  return (s:gsub(AMBIGUOUS_CLASS, ""))
end

--- True if s contains at least one ambiguous character.
function M.contains_ambiguous(s)
  compat.check_str(s, "s")
  return s:find(AMBIGUOUS_CLASS) ~= nil
end

--- Number of ambiguous characters in s.
function M.ambiguous_count(s)
  compat.check_str(s, "s")
  return select(2, s:gsub(AMBIGUOUS_CLASS, ""))
end

--- Per-set shrinkage report, handy for help text and tests.
-- e.g. counts.lower == 24 because 'l' and 'o' are ambiguous.
function M.ambiguous_counts()
  local counts = {}
  for i = 1, #SET_ORDER do
    local name = SET_ORDER[i]
    counts[name] = M.ambiguous_count(M.SETS[name])
  end
  return counts
end

-- ---------------------------------------------------------------------------
-- Set resolution
-- ---------------------------------------------------------------------------

--- Resolve user options into an ordered array of sets.
--
-- Accepted spellings, in priority order:
--   opts.sets             a string like "luds" (aliases l/u/d/s) or full
--                         names separated by nothing or spaces
--   opts.lower/upper/...  individual booleans
--   (nothing)             defaults to lower+upper+digits
--
-- opts.exclude_ambiguous (boolean) strips ambiguous characters from every
-- selected set. Returns an array of { name = string, chars = string }.
-- Fails with a passforge error on unknown names or fully-emptied sets.
function M.resolve_sets(opts)
  opts = opts or {}
  local chosen = {}
  local seen = {}

  local function add(name)
    if not M.SETS[name] then
      compat.fail("charsets", "unknown charset '%s'", tostring(name))
    end
    if not seen[name] then
      seen[name] = true
      chosen[#chosen + 1] = name
    end
  end

  local raw = opts.sets
  if type(raw) == "string" and #raw > 0 then
    for i = 1, #raw do
      local ch = raw:sub(i, i)
      if not ch:match("%s") then
        add(M.ALIASES[ch] or ch)
      end
    end
  else
    local any_flag = false
    for i = 1, #SET_ORDER do
      local name = SET_ORDER[i]
      if opts[name] then
        any_flag = true
        add(name)
      end
    end
    if not any_flag then
      add("lower")
      add("upper")
      add("digits")
    end
  end

  local out = {}
  for idx = 1, #chosen do
    local name = chosen[idx]
    local chars = M.SETS[name]
    if opts.exclude_ambiguous then
      chars = M.remove_ambiguous(chars)
    end
    if #chars == 0 then
      compat.fail("charsets", "charset '%s' is empty after ambiguity filtering", name)
    end
    out[idx] = { name = name, chars = chars }
  end

  if #out == 0 then
    compat.fail("charsets", "no charset selected")
  end
  return out
end

-- ---------------------------------------------------------------------------
-- Classification (password -> classes), used by the strength analyzer
-- ---------------------------------------------------------------------------

--- Class name of a single character: "lower", "upper", "digits", "symbols"
-- or "other". find(..., plain=true) is magic-char safe for e.g. "%".
function M.classify(ch)
  for i = 1, #SET_ORDER do
    local name = SET_ORDER[i]
    if M.SETS[name]:find(ch, 1, true) then
      return name
    end
  end
  return "other"
end

--- Count of each class in s: { lower = n, upper = n, digits = n,
-- symbols = n, other = n }.
function M.class_counts(s)
  compat.check_str(s, "s")
  local counts = { lower = 0, upper = 0, digits = 0, symbols = 0, other = 0 }
  for i = 1, #s do
    local name = M.classify(s:sub(i, i))
    counts[name] = counts[name] + 1
  end
  return counts
end

--- Sum of effective alphabet sizes for every class PRESENT in s.
-- This is the "pool size" the strength analyzer treats the password as if
-- it had been drawn from. An empty string yields 0.
function M.pool_size_for(s)
  local counts = M.class_counts(s)
  local total = 0
  for name, n in pairs(counts) do
    if n > 0 then
      total = total + M.CLASS_SIZE[name]
    end
  end
  return total
end

--- Human summary like "lower+upper+digits" (or "empty").
function M.describe_classes(s)
  local counts = M.class_counts(s)
  local parts = {}
  for i = 1, #SET_ORDER do
    local name = SET_ORDER[i]
    if counts[name] > 0 then
      parts[#parts + 1] = name
    end
  end
  if counts.other > 0 then
    parts[#parts + 1] = "other"
  end
  if #parts == 0 then
    return "empty"
  end
  return table.concat(parts, "+")
end

--- Expose the canonical order for other modules (read-only by convention).
function M.order()
  local copy = {}
  for i = 1, #SET_ORDER do
    copy[i] = SET_ORDER[i]
  end
  return copy
end

return M
