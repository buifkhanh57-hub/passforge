--- spec/harness.lua
-- Zero-dependency test harness for the passforge spec suite.
--
-- WHY NOT BUSTED/LUAUNIT
--   passforge has no external rocks by policy, so the specs ship their own
--   ~150-line harness. Same shape as the familiar frameworks:
--
--     local h = require("spec.harness")
--     h.suite("sha256", function()
--       h.it("empty string", function()
--         h.eq(sha256.hex(""), "e3b0...")
--       end)
--     end)
--
--   Registration happens at require time; execution happens when the runner
--   (spec/run.lua or `passforge selftest`) calls h.run_all().
--
-- ASSERTIONS
--   eq(a, b, msg)      deep equality; numbers compare with 1e-9 tolerance
--                      (entropy math crosses printf boundaries) unless both
--                      are integers
--   near(a, b, eps)    explicit tolerance
--   true_ / false_     boolean contracts
--   match(s, pattern)  string.find with a plain=false pattern must hit
--   raises(fn, prefix) fn must raise an error whose message starts with
--                      prefix (e.g. "passforge.generator:"); returns message
--   fail(msg)          unconditional failure
--
-- Everything runs on one global registry; a suite registers even when
-- another suite raised during registration (failures are reported per test).

local H = {}

H.suites = {}
H.stats = { suites = 0, tests = 0, passed = 0, failed = 0 }

local current_suite = nil

--- Register a suite; fn() runs immediately and calls it() to add tests.
function H.suite(name, fn)
  local s = { name = name, tests = {} }
  H.suites[#H.suites + 1] = s
  local previous = current_suite
  current_suite = s
  fn()
  current_suite = previous
  return s
end

--- Register one test inside the current suite.
function H.it(name, fn)
  if not current_suite then
    error("spec.harness: it() called outside suite()", 2)
  end
  current_suite.tests[#current_suite.tests + 1] = { name = name, fn = fn }
end

-- ---------------------------------------------------------------------------
-- Assertions
-- ---------------------------------------------------------------------------

local function is_integer(x)
  return type(x) == "number" and math.floor(x) == x
end

local function deep_eq(a, b, depth)
  depth = depth or 0
  if depth > 32 then
    return false
  end
  if a == b then
    return true
  end
  if type(a) ~= type(b) then
    return false
  end
  if type(a) == "number" then
    if is_integer(a) and is_integer(b) then
      return a == b
    end
    return math.abs(a - b) <= 1e-9
  end
  if type(a) ~= "table" then
    return false
  end
  local ka, kb = {}, {}
  for k in pairs(a) do
    ka[#ka + 1] = k
  end
  for k in pairs(b) do
    kb[#kb + 1] = k
  end
  if #ka ~= #kb then
    return false
  end
  for _, k in ipairs(ka) do
    if not deep_eq(a[k], b[k], depth + 1) then
      return false
    end
  end
  return true
end

--- Deep equality with numeric tolerance (see header).
function H.eq(actual, expected, msg)
  if not deep_eq(actual, expected) then
    error((msg or "eq failed") .. string.format(
      " - expected '%s', got '%s'", tostring(expected), tostring(actual)), 2)
  end
end

--- Equality within an explicit tolerance.
function H.near(actual, expected, eps, msg)
  if type(actual) ~= "number" or type(expected) ~= "number"
     or math.abs(actual - expected) > (eps or 1e-9) then
    error((msg or "near failed") .. string.format(
      " - expected %s +/- %s, got %s",
      tostring(expected), tostring(eps), tostring(actual)), 2)
  end
end

function H.true_(value, msg)
  if value ~= true then
    error((msg or "true_ failed") .. string.format(
      " - expected true, got '%s'", tostring(value)), 2)
  end
end

function H.false_(value, msg)
  if value ~= false then
    error((msg or "false_ failed") .. string.format(
      " - expected false, got '%s'", tostring(value)), 2)
  end
end

--- String must contain a Lua-pattern match (plain=false on purpose).
function H.match(s, pattern, msg)
  if type(s) ~= "string" or not s:find(pattern) then
    error((msg or "match failed") .. string.format(
      " - '%s' does not match pattern '%s'", tostring(s), tostring(pattern)), 2)
  end
end

--- fn() must raise; message must start with prefix (when given).
--- Returns the message for further inspection.
function H.raises(fn, prefix, msg)
  local ok, err = pcall(fn)
  if ok then
    error((msg or "raises failed") .. " - expected an error, none raised", 2)
  end
  err = tostring(err)
  if prefix and err:sub(1, #prefix) ~= prefix then
    error((msg or "raises failed") .. string.format(
      " - expected error starting with '%s', got '%s'", prefix, err), 2)
  end
  return err
end

--- Unconditional failure (control-flow guard in tests).
function H.fail(msg)
  error("fail: " .. tostring(msg), 2)
end

-- ---------------------------------------------------------------------------
-- Execution
-- ---------------------------------------------------------------------------

--- Run every registered suite. Returns 0 when everything passed, 1 otherwise.
-- Output goes to stdout so CI logs capture it verbatim.
function H.run_all()
  local width = 52
  for s = 1, #H.suites do
    local suite = H.suites[s]
    H.stats.suites = H.stats.suites + 1
    print(string.format("== %s", suite.name))
    for t = 1, #suite.tests do
      local test = suite.tests[t]
      H.stats.tests = H.stats.tests + 1
      local ok, err = pcall(test.fn)
      local status
      if ok then
        status = "ok  "
        H.stats.passed = H.stats.passed + 1
      else
        status = "FAIL"
        H.stats.failed = H.stats.failed + 1
      end
      local label = "  " .. status .. " " .. test.name
      if #label > width then
        label = label:sub(1, width - 1) .. "."
      end
      print(label)
      if not ok then
        print("       " .. tostring(err):gsub("\n", "\n       "))
      end
    end
  end
  print(string.format("== summary: %d suite(s), %d test(s), %d passed, %d failed",
    H.stats.suites, H.stats.tests, H.stats.passed, H.stats.failed))
  if H.stats.failed == 0 then
    return 0
  end
  return 1
end

--- Reset the registry (used by the meta-test of the harness itself).
function H.reset()
  H.suites = {}
  H.stats = { suites = 0, tests = 0, passed = 0, failed = 0 }
  current_suite = nil
end

return H
