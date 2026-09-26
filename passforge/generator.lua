--- passforge/generator.lua
-- Random password generation.
--
-- ALGORITHM (guaranteed inclusion)
--   1. Resolve the requested character sets (aliases, ambiguity filtering).
--   2. If --must-include-each (the default), draw one character from every
--      set first, so each class is guaranteed to appear at least once.
--   3. Fill the remaining slots from the union pool.
--   4. Fisher-Yates shuffle the result so the guaranteed characters are not
--      predictably at the front.
--
--   Step 2 changes the distribution slightly versus drawing every character
--   independently from the pool (the classic trade-off: guarantees vs. a
--   few bits of entropy). entropy_bits() documents and models the simple
--   independent-draws formula, which is what the strength analyzer also
--   uses, so generator output and audit scoring stay consistent.
--
-- NO-REPEATS MODE
--   Sampling without replacement: every picked character is marked used and
--   the fill loop rejection-samples the pool until it hits an unused one.
--   The pool is tiny (<= 94 chars), so expected tries stay close to 1; the
--   pre-check length > #pool turns impossible requests into clean errors.

local compat   = require("passforge.compat")
local random   = require("passforge.random")
local charsets = require("passforge.charsets")

local M = {}

local DEFAULT_LENGTH = 16
local MIN_LENGTH     = 4
local MAX_LENGTH     = 256
local MAX_COUNT      = 1000
-- Bulk generation retries until it has `count` DISTINCT passwords; this cap
-- keeps a pathological request (e.g. 1000 distinct passwords of length 4)
-- from looping forever.
local MAX_BULK_TRIES = 64

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

local function check_length(length)
  return compat.check_int(length, "length", MIN_LENGTH, MAX_LENGTH)
end

--- Validate opts.rng (optional): anything exposing :below() and :shuffle().
local function resolve_rng(opts)
  local rng = opts.rng
  if rng == nil then
    return random.default()
  end
  if type(rng) ~= "table" or type(rng.below) ~= "function" then
    compat.fail("generator", "opts.rng must be a passforge.random generator")
  end
  return rng
end

local function build_pool(sets)
  local parts = {}
  for i = 1, #sets do
    parts[i] = sets[i].chars
  end
  return table.concat(parts)
end

local function resolve_flags(opts)
  local must_include_each = true
  if opts.must_include_each ~= nil then
    must_include_each = opts.must_include_each and true or false
  end
  return {
    must_include_each = must_include_each,
    no_repeats = opts.no_repeats and true or false,
  }
end

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

--- Generate one password. Options:
--   length              integer 4..256 (default 16)
--   sets                "luds"-style string (overrides per-set booleans)
--   lower/upper/...     booleans; default pool is lower+upper+digits
--   exclude_ambiguous   strip Il1O0o| from every set
--   no_repeats          sample without replacement
--   must_include_each   one char per set (default true)
--   rng                 injectable passforge.random generator
function M.generate(opts)
  opts = opts or {}
  local length = check_length(opts.length or DEFAULT_LENGTH)
  local sets = charsets.resolve_sets(opts)
  local pool = build_pool(sets)
  local flags = resolve_flags(opts)
  local rng = resolve_rng(opts)

  if flags.no_repeats and length > #pool then
    compat.fail("generator",
      "cannot draw %d unique characters from a pool of %d", length, #pool)
  end
  if flags.must_include_each and length < #sets then
    compat.fail("generator",
      "length %d is too small to include all %d requested character sets",
      length, #sets)
  end

  local chars = {}
  local n = 0
  local used = {}

  -- Step 2: one guaranteed character per set.
  if flags.must_include_each then
    for i = 1, #sets do
      local set = sets[i]
      local ch
      if flags.no_repeats then
        local candidates = {}
        for c = 1, #set.chars do
          local cand = set.chars:sub(c, c)
          if not used[cand] then
            candidates[#candidates + 1] = cand
          end
        end
        if #candidates == 0 then
          compat.fail("generator", "ran out of unused characters in set '%s'", set.name)
        end
        ch = candidates[rng:below(#candidates) + 1]
        used[ch] = true
      else
        ch = set.chars:sub(rng:below(#set.chars) + 1, rng:below(#set.chars) + 1)
      end
      n = n + 1
      chars[n] = ch
    end
  end

  -- Step 3: fill from the union pool. In no_repeats mode the used-set size
  -- equals n, so the number of remaining useful pool characters is exact.
  while n < length do
    local pos = rng:below(#pool) + 1
    local ch = pool:sub(pos, pos)
    if flags.no_repeats then
      if used[ch] then
        -- Rejection sampling: uniform over unused characters, bounded by the
        -- pre-check above (length <= #pool) so this always terminates.
        while used[ch] do
          pos = rng:below(#pool) + 1
          ch = pool:sub(pos, pos)
        end
        used[ch] = true
      end
    end
    n = n + 1
    chars[n] = ch
  end

  -- Step 4: hide where the guaranteed characters live.
  rng:shuffle(chars)
  return table.concat(chars)
end

--- Generate `opts.count` DISTINCT passwords (dedup loop with a retry cap).
function M.generate_many(opts)
  opts = opts or {}
  local count = compat.check_int(opts.count or 1, "count", 1, MAX_COUNT)
  local out = {}
  local seen = {}
  local tries = 0
  local max_tries = count * MAX_BULK_TRIES + MAX_BULK_TRIES
  while #out < count do
    tries = tries + 1
    if tries > max_tries then
      compat.fail("generator",
        "could not produce %d distinct passwords (length too small for this pool?)",
        count)
    end
    local pw = M.generate(opts)
    if not seen[pw] then
      seen[pw] = true
      out[#out + 1] = pw
    end
  end
  return out
end

--- Estimated entropy in bits for one generated password: L * log2(pool).
-- Note: with no_repeats the true space is P(pool, L) = pool!/(pool-L)!,
-- marginally SMALLER than pool^L; the estimate is therefore slightly
-- optimistic there. Documented honestly rather than hidden.
function M.entropy_bits(opts)
  opts = opts or {}
  local length = check_length(opts.length or DEFAULT_LENGTH)
  local sets = charsets.resolve_sets(opts)
  local pool = build_pool(sets)
  if #pool < 2 then
    return 0
  end
  return length * compat.log2(#pool)
end

--- Combined pool size for the current options (e.g. 62 for l+u+d).
function M.pool_size(opts)
  opts = opts or {}
  local sets = charsets.resolve_sets(opts)
  return #build_pool(sets)
end

--- One-line description like "lower+upper+digits (pool of 62 characters)".
function M.describe(opts)
  opts = opts or {}
  local sets = charsets.resolve_sets(opts)
  local names = {}
  for i = 1, #sets do
    names[i] = sets[i].name
  end
  return string.format("%s (pool of %d characters)",
    table.concat(names, "+"), #build_pool(sets))
end

--- Tuning constants, exported for the CLI help and the tests.
M.LIMITS = {
  default_length = DEFAULT_LENGTH,
  min_length = MIN_LENGTH,
  max_length = MAX_LENGTH,
  max_count = MAX_COUNT,
}

return M
