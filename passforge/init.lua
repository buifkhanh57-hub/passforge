--- passforge/init.lua
-- Library entry point for the passforge toolkit.
--
-- Requiring "passforge" loads the library modules (the ones the CLI in
-- passforge/cli.lua composes) and returns them as one table, so embedders
-- can write:
--
--   local pf = require("passforge")
--   local pw = pf.generator.generate({ length = 20, sets = "luds" })
--
-- The CLI itself is deliberately NOT required here: bin/passforge loads
-- passforge.cli directly, and embedding hosts that only want the crypto /
-- generation primitives should not pay for command-line plumbing.
-- Every module filename below matches a real file in this directory;
-- load order follows the dependency graph (compat first, tips/audit last).

return {
  compat    = require("passforge.compat"),
  charsets  = require("passforge.charsets"),
  json      = require("passforge.json"),
  sha256    = require("passforge.sha256"),
  random    = require("passforge.random"),
  wordlist  = require("passforge.wordlist"),
  generator = require("passforge.generator"),
  passphrase = require("passforge.passphrase"),
  entropy   = require("passforge.entropy"),
  strength  = require("passforge.strength"),
  tips      = require("passforge.tips"),
  audit     = require("passforge.audit"),
  version   = require("passforge.version"),
}
