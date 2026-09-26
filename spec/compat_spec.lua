--- spec/compat_spec.lua
-- Contract tests for the Lua 5.1-5.4 compatibility layer.
--
-- These tests pin the FUNCTIONAL contract (what each helper returns), not
-- the backend: they must pass identically on bit32 (5.2), LuaJIT bit, and
-- the pure-arithmetic fallback. compat.selftest() covers a few extra
-- known-answer checks that live next to the implementation.

local h       = require("spec.harness")
local compat  = require("passforge.compat")

h.suite("compat", function()

  h.it("exposes the module constants", function()
    h.eq(compat.WIDTH, 32, "width")
    h.eq(compat.MOD, 4294967296, "2^32 modulus")
    h.eq(compat.MASK, 4294967295, "all-ones mask")
    h.near(compat.LN2, 0.6931471805599453, 1e-15, "ln(2)")
  end)

  h.it("reports a known backend name", function()
    local name = compat.backend()
    h.true_(name == "bit32" or name == "bit" or name == "pure",
      "backend must be bit32/bit/pure, got " .. tostring(name))
  end)

  h.it("band matches truth tables", function()
    h.eq(compat.band(0xF0F0, 0x0FF0), 0x00F0, "band nibbles")
    h.eq(compat.band(0xFFFFFFFF, 0x00000000), 0, "band zero")
    h.eq(compat.band(0x12345678, 0xFFFFFFFF), 0x12345678, "band identity")
  end)

  h.it("bor and bxor match truth tables", function()
    h.eq(compat.bor(0xF0F0, 0x0F0F), 0xFFFF, "bor")
    h.eq(compat.bor(0x80000000, 0x1), 0x80000001, "bor high bit")
    h.eq(compat.bxor(0xFF00, 0x0FF0), 0xF0F0, "bxor")
    h.eq(compat.bxor(0xFF, 0xFF), 0, "bxor self")
    h.eq(compat.bxor(0, 0), 0, "bxor zero")
  end)

  h.it("bnot is a 32-bit two's complement mirror", function()
    h.eq(compat.bnot(0), 0xFFFFFFFF, "bnot 0")
    h.eq(compat.bnot(0xFFFFFFFF), 0, "bnot all-ones")
    h.eq(compat.bnot(compat.bnot(0x5A5A5A5A)), 0x5A5A5A5A, "bnot involution")
  end)

  h.it("shifts behave like bit32 at the edges", function()
    h.eq(compat.lshift(1, 0), 1, "lshift 0")
    h.eq(compat.lshift(1, 31), 0x80000000, "lshift 31")
    h.eq(compat.lshift(1, 32), 0, "lshift 32 saturates")
    h.eq(compat.lshift(3, 4), 48, "lshift small")
    h.eq(compat.rshift(0x80000000, 31), 1, "rshift 31")
    h.eq(compat.rshift(0x80000000, 32), 0, "rshift 32 saturates")
    h.eq(compat.rshift(48, 4), 3, "rshift small")
  end)

  h.it("negative shift counts delegate to the opposite direction", function()
    h.eq(compat.lshift(1, -2), compat.rshift(1, 2), "lshift negative")
    h.eq(compat.rshift(16, -2), compat.lshift(16, 2), "rshift negative")
  end)

  h.it("rrotate wraps bits, never zeroes them", function()
    h.eq(compat.rrotate(0x80000001, 1), 0xC0000000, "rotate pair")
    h.eq(compat.rrotate(0x00000001, 4), 0x10000000, "rotate low nibble")
    h.eq(compat.rrotate(0xDEADBEEF, 0), 0xDEADBEEF, "rotate 0")
    h.eq(compat.rrotate(0x12345678, 32), 0x12345678, "rotate full width")
    h.eq(compat.rrotate(0x12345678, 16),
         compat.rrotate(compat.rrotate(0x12345678, 8), 8), "rotation splits")
  end)

  h.it("inputs are masked to 32 bits first", function()
    h.eq(compat.band(4294967296 + 1, 4294967296 + 3), 1, "mask before band")
    h.eq(compat.bnot(4294967296), 0xFFFFFFFF, "mask before bnot")
  end)

  h.it("add32 wraps modulo 2^32 and is variadic", function()
    h.eq(compat.add32(0xFFFFFFFF, 2), 1, "wrap")
    h.eq(compat.add32(0xFFFFFFFF, 0xFFFFFFFF), 0xFFFFFFFE, "double wrap")
    h.eq(compat.add32(1, 2, 3, 4, 5), 15, "variadic")
    h.eq(compat.add32(), 0, "no arguments")
  end)

  h.it("log2 is exact on powers of two", function()
    h.near(compat.log2(1), 0, 1e-12, "log2 1")
    h.near(compat.log2(8), 3, 1e-12, "log2 8")
    h.near(compat.log2(1024), 10, 1e-12, "log2 1024")
    h.near(compat.log2(62), math.log(62) / math.log(2), 1e-12, "log2 62")
  end)

  h.it("unpack exists on every interpreter", function()
    h.eq(type(compat.unpack), "function", "unpack type")
    local a, b = compat.unpack({ 10, 20 })
    h.eq(a, 10, "unpack first")
    h.eq(b, 20, "unpack second")
  end)

  h.it("check_int validates type and bounds", function()
    h.eq(compat.check_int("42", "x"), 42, "numeric strings coerce")
    h.eq(compat.check_int(7.0, "x"), 7, "integral floats pass")
    h.raises(function() compat.check_int("abc", "x") end,
      "passforge.compat:", "non-numeric")
    h.raises(function() compat.check_int(3.5, "x") end,
      "passforge.compat:", "fractional")
    h.raises(function() compat.check_int(2, "x", 3) end,
      "passforge.compat:", "below lo")
    h.raises(function() compat.check_int(9, "x", 1, 5) end,
      "passforge.compat:", "above hi")
    h.eq(compat.check_int(5, "x", 1, 10), 5, "in range passes")
  end)

  h.it("check_str rejects empty and non-strings", function()
    h.eq(compat.check_str("ok", "s"), "ok", "good string")
    h.raises(function() compat.check_str("", "s") end,
      "passforge.compat:", "empty string")
    h.raises(function() compat.check_str(42, "s") end,
      "passforge.compat:", "number input")
    h.raises(function() compat.check_str(nil, "s") end,
      "passforge.compat:", "nil input")
  end)

  h.it("fail builds the namespaced message with level 0", function()
    local err = h.raises(function()
      compat.fail("some.module", "bad thing %d", 7)
    end, "passforge.some.module:", "namespaced")
    h.match(err, "bad thing 7$", "formatted tail")
  end)

  h.it("selftest passes on the active backend", function()
    h.eq(compat.selftest(), true, "selftest")
  end)

end)
