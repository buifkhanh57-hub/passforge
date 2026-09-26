--- passforge/version.lua
-- Single source of truth for passforge identity metadata.
--
-- Every user-facing string (CLI banner, --version output, README badges,
-- generated reports) reads from this table so the version number can never
-- drift between components. Keep it dependency-free: nothing else may be
-- required from inside this file.

return {
  -- Package identity ---------------------------------------------------------
  name        = "passforge",
  version     = "1.0.0",
  codename    = "anvil",

  -- One-line pitch, reused by the CLI banner and the JSON "about" payload ----
  description = "Professional password generator and auditor toolkit",

  -- Authorship / legal -------------------------------------------------------
  author      = "Bui Bao Khanh",
  license     = "MIT",
  homepage    = "https://github.com/buifkhanh57-hub/passforge",

  -- Technical envelope -------------------------------------------------------
  -- Pure Lua, no external rocks, no C bindings. The bitwise compatibility
  -- layer in compat.lua makes the whole toolkit run unchanged on:
  lua_target  = "5.1 - 5.4",
  interpreters = {
    "lua 5.1",
    "lua 5.2 (bit32 backend)",
    "lua 5.3",
    "lua 5.4",
    "luajit 2.0+ (bit backend)",
  },

  -- Search keywords, handy for GitHub "about" topics --------------------------
  keywords = {
    "password",
    "passphrase",
    "generator",
    "auditor",
    "entropy",
    "security",
    "sha256",
    "cli",
  },
}
