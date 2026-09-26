--- spec/run.lua
-- Spec-suite entry point.
--
-- Two ways to run it:
--   lua spec/run.lua           (from the repository root)
--   passforge selftest         (bin shim puts the repo on package.path)
--
-- Requiring this module loads every spec file (registration side effects),
-- then exposes run_all() -> exit code. Requiring it a second time is a
-- no-op thanks to package.loaded, which also protects `passforge selftest`
-- from recursion if it were ever invoked from inside the suite.

if not _G.__PASSFORGE_SPECS_LOADED then
  _G.__PASSFORGE_SPECS_LOADED = true
end

local harness = require("spec.harness")

-- Registration order = execution order; keep it stable and grouped by
-- module so a failure's context is obvious in CI logs.
-- Suites shipped in this release: compat, json, sha256 (FIPS 180-4
-- known-answer vectors). The remaining library modules are covered by
-- load-time invariant checks inside passforge/ itself (e.g. the wordlist
-- uniqueness guard, charsets sanity, entropy SCALE ordering).
require("spec.compat_spec")
require("spec.json_spec")
require("spec.sha256_spec")

local M = {}

--- Execute all registered suites; returns 0 (all green) or 1 (failures).
function M.run_all()
  return harness.run_all()
end

--- Number of tests registered (exposed so run.lua can assert it loaded
-- everything before executing anything).
function M.registered()
  local total = 0
  for s = 1, #harness.suites do
    total = total + #harness.suites[s].tests
  end
  return total
end

-- Direct execution: `lua spec/run.lua` from the repository root.
if arg and type(arg[0]) == "string" and arg[0]:find("spec[/\\]run%.lua$") then
  os.exit(M.run_all())
end

return M
