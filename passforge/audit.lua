--- passforge/audit.lua
-- Batch audit orchestration: turns raw passwords into decision-ready
-- reports, one password at a time or a whole list at once.
--
-- POSITION IN THE STACK
--   strength.lua answers "how weak is THIS string?".
--   audit.lua answers "what did we just look at, what should we do, and
--   how does it compare to the rest of the batch?" - it composes
--   strength.analyze() with tips.for_analysis(), masks secrets by default
--   and computes batch statistics (mean/median/spread/score histogram).
--
-- SECRET HANDLING
--   Reports carry a MASKED form of the password (first and last character
--   only, e.g. "f******t") unless opts.reveal is set. This keeps --json
--   dumps, logs and CI artifacts safe to share by default.

local compat   = require("passforge.compat")
local strength = require("passforge.strength")
local tips     = require("passforge.tips")

local M = {}

-- Local rounding helper: keeps audit.lua free of a circular dependency on
-- entropy.lua (strength already imports it; duplicating one 3-liner is the
-- cheaper trade for a flat dependency graph).
local function entropy_round(x)
  return math.floor(x * 100 + 0.5) / 100
end

--- Mask a secret for reports: keep first/last character, star the rest.
-- Short secrets (<= 4 chars) are fully starred. Empty -> "<empty>".
function M.mask(pw)
  if type(pw) ~= "string" then
    return "<none>"
  end
  local n = #pw
  if n == 0 then
    return "<empty>"
  end
  if n <= 4 then
    return string.rep("*", n)
  end
  return pw:sub(1, 1) .. string.rep("*", n - 2) .. pw:sub(n, n)
end

--- Arithmetic mean of a numeric array; 0 for an empty array.
function M.mean(numbers)
  local n = #numbers
  if n == 0 then
    return 0
  end
  local total = 0
  for i = 1, n do
    total = total + numbers[i]
  end
  return total / n
end

--- Median of a numeric array (average of the two middles for even counts).
-- The input array is copied before sorting; the caller's order is kept.
function M.median(numbers)
  local n = #numbers
  if n == 0 then
    return 0
  end
  local copy = {}
  for i = 1, n do
    copy[i] = numbers[i]
  end
  table.sort(copy)
  local mid = math.ceil(n / 2)
  if n % 2 == 1 then
    return copy[mid]
  end
  return (copy[mid] + copy[mid + 1]) / 2
end

--- Full report for ONE password.
-- opts.reveal (bool)    include the plaintext in report.password
-- opts.no_tips (bool)   skip the recommendation pass
function M.audit_one(pw, opts)
  if type(pw) ~= "string" then
    compat.fail("audit", "audit_one expects a string, got '%s'", type(pw))
  end
  opts = opts or {}
  local analysis = strength.analyze(pw)

  local findings = {}
  for i = 1, #analysis.findings do
    local f = analysis.findings[i]
    findings[i] = {
      id = f.id,
      severity = f.severity,
      title = f.title,
      detail = f.detail,
      penalty = f.penalty,
    }
  end

  local advice = {}
  if not opts.no_tips then
    advice = tips.for_analysis(analysis)
  end

  local report = {
    password = opts.reveal and pw or nil,
    password_masked = M.mask(pw),
    password_length = analysis.length,
    classes = analysis.classes,
    pool_size = analysis.pool_size,
    pool_bits = analysis.pool_bits,
    unique_bits = analysis.unique_bits,
    shannon_bits = analysis.shannon_bits,
    base_bits = analysis.base_bits,
    deductions = analysis.deductions,
    entropy_bits = analysis.entropy_bits,
    score = analysis.score,
    verdict = analysis.verdict,
    is_common = analysis.is_common,
    common_rank = analysis.common_rank,
    crack = {},
    findings = findings,
    tips = advice,
  }
  for i = 1, #analysis.crack do
    local c = analysis.crack[i]
    report.crack[i] = {
      id = c.id,
      label = c.label,
      rate = c.rate,
      human = c.human,
    }
  end
  return report
end

--- One-line human summary of a single report.
function M.summary_line(report)
  return string.format("%-10s %6.2f bits  score %d/5  %s", report.verdict,
    report.entropy_bits, report.score, report.password_masked)
end

--- Audit a list of passwords (array of strings). Options pass through to
-- audit_one; opts.on_result(entry) is invoked per result for streaming UIs.
-- Returns { count, results = {...}, summary = {...} }.
function M.audit_many(passwords, opts)
  if type(passwords) ~= "table" then
    compat.fail("audit", "audit_many expects an array of strings")
  end
  opts = opts or {}

  local results = {}
  local bits = {}
  local histogram = { 0, 0, 0, 0, 0, 0 }
  local common_count = 0
  local weak_count = 0
  local strong_count = 0
  local weakest_index, strongest_index
  local unique = {}

  for i = 1, #passwords do
    local pw = passwords[i]
    if type(pw) ~= "string" then
      compat.fail("audit", "password #%d is not a string", i)
    end
    local entry = M.audit_one(pw, opts)
    entry.index = i
    results[i] = entry
    bits[i] = entry.entropy_bits
    histogram[entry.score + 1] = histogram[entry.score + 1] + 1
    if entry.is_common then
      common_count = common_count + 1
    end
    if entry.score <= 1 then
      weak_count = weak_count + 1
    end
    if entry.score >= 3 then
      strong_count = strong_count + 1
    end
    unique[entry.entropy_bits] = (unique[entry.entropy_bits] or 0) + 1
    if not weakest_index or entry.entropy_bits < results[weakest_index].entropy_bits then
      weakest_index = i
    end
    if not strongest_index or entry.entropy_bits > results[strongest_index].entropy_bits then
      strongest_index = i
    end
    if opts.on_result then
      opts.on_result(entry)
    end
  end

  local distinct = 0
  for _ in pairs(unique) do
    distinct = distinct + 1
  end

  local summary = {
    count = #results,
    mean_bits = entropy_round(M.mean(bits)),
    median_bits = entropy_round(M.median(bits)),
    min_bits = #bits > 0 and entropy_round(bits[weakest_index]) or 0,
    max_bits = #bits > 0 and entropy_round(bits[strongest_index]) or 0,
    weakest = weakest_index and results[weakest_index].password_masked or nil,
    strongest = strongest_index and results[strongest_index].password_masked or nil,
    weakest_index = weakest_index,
    strongest_index = strongest_index,
    histogram = histogram,
    verdict_counts = {
      [0] = histogram[1], [1] = histogram[2], [2] = histogram[3],
      [3] = histogram[4], [4] = histogram[5], [5] = histogram[6],
    },
    common_count = common_count,
    weak_count = weak_count,
    strong_count = strong_count,
    distinct_bit_levels = distinct,
  }
  return { count = #results, results = results, summary = summary }
end

--- One-line human summary of a batch.
function M.batch_summary_line(batch)
  local s = batch.summary
  return string.format(
    "%d password%s: mean %.2f bits, median %.2f bits, %d weak, %d strong",
    s.count, s.count == 1 and "" or "s", s.mean_bits, s.median_bits,
    s.weak_count, s.strong_count)
end

--- Exit-code policy for CI: fail (1) when any password scores below the
-- given threshold. Returns true when the batch would fail.
function M.fails_threshold(batch, min_score)
  min_score = tonumber(min_score)
  if not min_score then
    return false
  end
  for i = 1, #batch.results do
    if batch.results[i].score < min_score then
      return true
    end
  end
  return false
end

--- Quick sanity check used by the spec suite.
function M.selftest()
  assert(M.mask("abc") == "***", "mask short")
  assert(M.mask("") == "<empty>", "mask empty")
  local m = M.mask("hunter2secret")
  assert(m:sub(1, 1) == "h" and m:sub(-1) == "t" and #m == 14, "mask keeps ends")
  assert(M.median({ 5, 1, 3 }) == 3, "median odd")
  assert(M.median({ 4, 1, 3, 2 }) == 2.5, "median even")
  assert(M.mean({ 2, 4 }) == 3, "mean")
  local batch = M.audit_many({ "123456", "correct horse battery staple" }, {})
  assert(batch.count == 2, "batch count")
  assert(batch.summary.weak_count >= 1, "123456 is weak")
  assert(M.fails_threshold(batch, 3) == true, "threshold triggers")
  assert(M.fails_threshold(batch, nil) == false, "no threshold, no fail")
  return true
end

return M
