--- passforge/tips.lua
-- Contextual recommendations engine.
--
-- The other modules ANSWER questions ("how strong is this?", "how many
-- bits does this mode yield?"); this module tells the user WHAT TO DO NEXT.
-- Every tip is derived from a concrete measurement taken elsewhere in the
-- toolkit - a finding id from strength.analyze(), an option value from the
-- generator - so the advice can never drift away from the numbers that
-- triggered it.
--
-- TIP SHAPE
--   { id       = stable machine-readable id (deduplication key)
--     severity = "critical" | "warning" | "info" | "tip"
--     title    = short imperative
--     why      = the measured reason (quotes the numbers)
--     how      = the concrete action, usually with a suggested command }
--
-- The engine is deliberately conservative: it only speaks when it has
-- something measured to say, and `combine()` deduplicates by id so several
-- detectors confirming the same problem produce one strong tip instead of
-- four noisy ones.

local compat   = require("passforge.compat")
local charsets = require("passforge.charsets")
local entropy  = require("passforge.entropy")
local strength = require("passforge.strength")
local wordlist = require("passforge.wordlist")

local M = {}

M.MAX_TIPS = 8

M.SEVERITY = { critical = 1, warning = 2, info = 3, tip = 4 }
M.SEVERITY_ORDER = { "critical", "warning", "info", "tip" }

local function tip(id, severity, title, why, how)
  return { id = id, severity = severity, title = title, why = why, how = how }
end

--- Numeric rank of a severity for sorting (unknown severities sort last).
function M.severity_rank(sev)
  return M.SEVERITY[sev] or 99
end

--- Sort tips by severity (critical first), keeping insertion order inside
-- a severity class. Returns a new array; the input is not modified.
function M.sort(list)
  local copy = {}
  for i = 1, #list do
    copy[i] = list[i]
  end
  table.sort(copy, function(a, b)
    local ra, rb = M.severity_rank(a.severity), M.severity_rank(b.severity)
    if ra ~= rb then
      return ra < rb
    end
    return a.id < b.id
  end)
  return copy
end

--- Merge tip lists, dedupe by id, sort, and cap at M.MAX_TIPS.
-- Passing no lists is valid and returns an empty array.
function M.combine(...)
  local merged = {}
  local seen = {}
  local lists = { ... }
  for l = 1, #lists do
    local list = lists[l]
    if type(list) == "table" then
      for i = 1, #list do
        local item = list[i]
        if type(item) == "table" and item.id and not seen[item.id] then
          seen[item.id] = true
          merged[#merged + 1] = item
        end
      end
    end
  end
  merged = M.sort(merged)
  while #merged > M.MAX_TIPS do
    table.remove(merged)
  end
  return merged
end

--- One-line rendering used by the CLI text mode.
function M.format_tip(t)
  return string.format("[%s] %s - %s", t.severity, t.title, t.why)
end

-- ---------------------------------------------------------------------------
-- Password-side tips (input: a strength.analyze() report)
-- ---------------------------------------------------------------------------

--- Concrete suggestion numbers reused by several tips: what a 16-character
-- full-pool draw would score, and what a 5-word passphrase yields.
local function reference_numbers()
  local pool = 94
  local gen_bits = entropy.bits_from_pool(pool, 16)
  local pass_bits = 5 * wordlist.bits_per_word()
  return {
    gen_bits = entropy.round2(gen_bits),
    gen_pool = pool,
    pass_bits = entropy.round2(pass_bits),
    pass_words = 5,
  }
end

--- Tips derived from an analysis report. Order inside the returned array is
-- by severity already; `combine` (used by audit.lua) re-sorts after merging.
function M.for_analysis(report)
  if type(report) ~= "table" or type(report.findings) ~= "table" then
    compat.fail("tips", "for_analysis expects a strength.analyze() report")
  end
  local out = {}
  local ref = reference_numbers()
  local findings = report.findings

  local function has(id)
    for i = 1, #findings do
      if findings[i].id == id then
        return findings[i]
      end
    end
    return nil
  end

  if report.length == 0 then
    out[#out + 1] = tip("empty", "critical",
      "Set a password - there is nothing to protect this account yet",
      "An empty string grants access to anyone.",
      "passforge gen --length 16")
    return M.sort(out)
  end

  if report.is_common then
    out[#out + 1] = tip("corpus-hit", "critical",
      "Replace this password immediately",
      string.format(
        "It (or a trivial variant) sits at rank #%d on the public breach corpus; automated attacks try it in the first second.",
        report.common_rank or 0),
      "passforge gen --length 16 --json")
  end

  if has("too-short") then
    out[#out + 1] = tip("raise-length", "critical",
      string.format("Use at least %d characters (16 is better)", strength.MIN_GOOD_LENGTH),
      string.format("Length is the strongest lever: this password sits at %.2f bits, a 16-character full-pool draw sits at ~%.0f.",
        report.entropy_bits, ref.gen_bits),
      "passforge gen --length 16")
  end

  if has("single-class") then
    out[#out + 1] = tip("mix-classes", "warning",
      "Mix character classes",
      string.format(
        "Only the '%s' class appears, so the effective pool is tiny compared to the 94-character full keyboard.",
        report.classes),
      "passforge gen --sets luds --length 16")
  end

  if has("sequence") or has("keyboard-walk") then
    out[#out + 1] = tip("avoid-patterns", "warning",
      "Break up keyboard and alphabet patterns",
      "Sequences like 'abc' or 'qwe' are enumerated by every cracking tool before anything else.",
      "passforge gen --length 16 --no-require-each")
  end

  if has("repeat") then
    out[#out + 1] = tip("avoid-repeats", "warning",
      "Avoid repeated characters and cycles",
      "Runs like 'aaa' or 'ababab' collapse large parts of the keyspace.",
      "passforge gen --length 16 --no-repeats")
  end

  if has("year") or has("date") then
    out[#out + 1] = tip("drop-year", "warning",
      "Do not build passwords around years or dates",
      "Birth/anniversary years are the first affixes attackers enumerate (only ~200 useful values).",
      "passforge gen --length 16")
  end

  if has("dictionary-word") then
    out[#out + 1] = tip("dictionary", "warning",
      "Dictionary words need distance or more words",
      string.format(
        "The embedded 1024-word list already contains this word; either switch to random characters or commit to 5+ random words (~%.0f bits).",
        ref.pass_bits),
      "passforge pass --words 5")
  end

  if has("leet-speak") then
    out[#out + 1] = tip("leet", "info",
      "Leet substitutions are cosmetic",
      "Swapping a->4 and e->3 is in every cracking rule set; it adds almost no real entropy.",
      "passforge strength '<new password>'")
  end

  if report.score >= 3 and report.score <= 4 and not report.is_common then
    out[#out + 1] = tip("good-so-far", "tip",
      "Solid password - protect it operationally",
      string.format("%.2f bits is respectable; the remaining risks are reuse and phishing, not brute force.",
        report.entropy_bits),
      "Store it in a password manager and never reuse it across sites.")
  end

  if report.score == 5 then
    out[#out + 1] = tip("excellent", "tip",
      "Excellent entropy",
      string.format("%.2f bits exceeds what any realistic offline attack can enumerate.", report.entropy_bits),
      "Consider a passphrase of 6+ words instead if you also need to memorize it.")
  end

  return M.sort(out)
end

-- ---------------------------------------------------------------------------
-- Generation-side tips (input: mode string + options table)
-- ---------------------------------------------------------------------------

local function pool_with_ambiguous(opts)
  local copy = {}
  for k, v in pairs(opts) do
    copy[k] = v
  end
  copy.exclude_ambiguous = false
  local sets = charsets.resolve_sets(copy)
  local total = 0
  for i = 1, #sets do
    total = total + #sets[i].chars
  end
  return total
end

local function pool_without_ambiguous(opts)
  local copy = {}
  for k, v in pairs(opts) do
    copy[k] = v
  end
  copy.exclude_ambiguous = true
  local sets = charsets.resolve_sets(copy)
  local total = 0
  for i = 1, #sets do
    total = total + #sets[i].chars
  end
  return total
end

--- Tips about generation settings. mode is "gen" or "pass"; opts accepts the
-- same fields as generator.generate() / passphrase.build(). The CLI wires
-- `passforge tips --mode gen ...` here.
function M.for_generation(mode, opts)
  opts = opts or {}
  local out = {}

  if mode == "gen" then
    local length = opts.length or 16
    local with = pool_with_ambiguous(opts)
    local bits = entropy.bits_from_pool(with, length)
    local verdict = entropy.scale_for(bits)

    if verdict.score < 3 then
      out[#out + 1] = tip("gen-weak", "warning",
        string.format("These settings yield only %.2f bits", bits),
        string.format("%d characters from a %d-character pool is below the 'strong' threshold of 60 bits.",
          length, with),
        "Raise --length to 16 or add sets with --sets luds")
    end

    if length < 12 then
      out[#out + 1] = tip("gen-short", "warning",
        "Prefer 12+ characters, 16 for high-value accounts",
        string.format("At length %d even the full 94-key pool gives %.2f bits; every extra character multiplies the keyspace by 94.",
          length, entropy.bits_from_pool(94, length)),
        "passforge gen --length 16")
    end

    if opts.exclude_ambiguous then
      local without = pool_without_ambiguous(opts)
      if without < with then
        local lost = entropy.round2(bits - entropy.bits_from_pool(without, length))
        out[#out + 1] = tip("ambiguous-cost", "info",
          "Ambiguity filtering costs a little entropy",
          string.format("Removing Il1O0o| shrinks the pool from %d to %d characters (~%.2f bits at this length). A fair trade for readability - just know the price.",
            with, without, lost),
          "Keep --no-ambiguous for passwords humans must re-type")
      end
    end

    if not (opts.sets and opts.sets:find("s")) and not opts.symbols then
      out[#out + 1] = tip("add-symbols", "tip",
        "Symbols widen the pool",
        string.format("Adding the 32-symbol class grows this pool from %d to %d characters.",
          with, with + 32),
        "passforge gen --sets luds --length 16")
    end

    if opts.no_repeats then
      out[#out + 1] = tip("no-repeats", "info",
        "no-repeats slightly reduces the honest keyspace",
        "Sampling without replacement draws from pool!/(pool-L)! rather than pool^L; the estimate shown elsewhere is a touch optimistic.",
        "Drop --no-repeats for maximum theoretical entropy")
    end

    if opts.must_include_each == false then
      out[#out + 1] = tip("require-each", "info",
        "Set guarantees are disabled",
        "Without one-character-per-set enforcement a draw may contain no digit at all - fine statistically, surprising in practice.",
        "passforge gen --length 16  (guarantees are on by default)")
    end

    if opts.seed then
      out[#out + 1] = tip("seed-danger", "critical",
        "Deterministic seeding is for tests only",
        "A fixed --seed reproduces the exact same passwords every run; anyone who learns the seed learns every password.",
      "NEVER use --seed for real credentials")
    end
  elseif mode == "pass" then
    local words = opts.words or 5
    if words > 24 then
      words = 24
    end
    local bits = words * wordlist.bits_per_word()
    local verdict = entropy.scale_for(bits)

    out[#out + 1] = tip("wordlist-public", "tip",
      "The wordlist is public - and that is fine",
      string.format(
        "Attackers know the %d embedded words; all security comes from WHICH words were drawn (%.2f bits/word, %.2f bits total).",
        wordlist.count(), wordlist.bits_per_word(), bits),
      "Never hand-pick words; always let the generator draw them")

    if verdict.score < 3 then
      out[#out + 1] = tip("pass-weak", "warning",
        string.format("%d words give %.2f bits", words, bits),
        "Below 60 bits this is fair-game for large offline attacks; each extra word adds a flat 10 bits.",
        "passforge pass --words 6")
    end

    if opts.append_digit then
      out[#out + 1] = tip("pass-digit", "info",
        "The appended digit adds ~3.32 bits",
        "log2(10) is real entropy but small; treat the digit as a foot-gun against reuse rules, not as security.",
        "Add a word instead: passforge pass --words 5")
    end

    if opts.capitalize then
      out[#out + 1] = tip("pass-cap", "info",
        "Capitalization adds no entropy",
        "Given the same word list and options, the capitalized form is fully predictable - it only helps readability.",
        "Keep --cap for typing, count words for strength")
    end
  else
    compat.fail("tips", "for_generation mode must be 'gen' or 'pass', got '%s'",
      tostring(mode))
  end

  return M.sort(out)
end

--- Convenience wrapper: tips for an entropy.estimate_generate /
--- estimate_passphrase table (used by `passforge entropy --tips`).
function M.for_estimate(estimate)
  if type(estimate) ~= "table" or estimate.mode == nil then
    compat.fail("tips", "for_estimate expects an entropy estimate table")
  end
  local mode = estimate.mode == "pass" and "pass" or "gen"
  return M.for_generation(mode, estimate)
end

--- Quick sanity check used by the spec suite.
function M.selftest()
  local report = strength.analyze("123456")
  local tips = M.for_analysis(report)
  assert(#tips > 0, "common password yields tips")
  assert(tips[1].severity == "critical", "corpus hit sorts first")
  local ids = {}
  for i = 1, #tips do
    ids[tips[i].id] = true
  end
  assert(ids["corpus-hit"], "corpus-hit present")
  local merged = M.combine(
    { { id = "a", severity = "info", title = "", why = "", how = "" },
      { id = "b", severity = "critical", title = "", why = "", how = "" } },
    { { id = "a", severity = "info", title = "", why = "", how = "" } })
  assert(#merged == 2, "combine dedupes by id")
  assert(merged[1].id == "b", "critical sorts before info")
  return true
end

return M
