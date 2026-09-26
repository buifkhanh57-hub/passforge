--- spec/json_spec.lua
-- Contract tests for the dependency-free JSON encoder.
--
-- passforge only ever WRITES JSON, so the encoder is checked against the
-- grammar rules that matter for consumers: valid scalar rendering,
-- deterministic key order, correct escaping, array-vs-object detection and
-- the failure modes (NaN, function values, runaway nesting).

local h      = require("spec.harness")
local json   = require("passforge.json")
local compat = require("passforge.compat")

h.suite("json", function()

  h.it("encodes scalars", function()
    h.eq(json.encode(nil), "null", "nil")
    h.eq(json.encode(true), "true", "true")
    h.eq(json.encode(false), "false", "false")
    h.eq(json.encode(0), "0", "zero")
    h.eq(json.encode(-7), "-7", "negative integer")
    h.eq(json.encode(3.0), "3", "integral float stays integer-shaped")
    h.eq(json.encode(0.5), "0.5", "fraction")
    h.eq(json.encode("hi"), '"hi"', "plain string")
  end)

  h.it("renders floats without float noise", function()
    h.eq(json.encode(1 / 3), string.format("%.14g", 1 / 3), "14 significant digits")
    h.eq(json.encode(100), "100", "integral value")
    h.eq(json.encode(2 ^ 53), "9007199254740992", "2^53 stays exact")
  end)

  h.it("escapes strings correctly", function()
    h.eq(json.encode('say "hi"'), '"say \\"hi\\""', "quotes")
    h.eq(json.encode("back\\slash"), '"back\\\\slash"', "backslash first")
    h.eq(json.encode("line\nbreak"), '"line\\u000abreak"', "control char")
    h.eq(json.encode("tab\there"), '"tab\\u0009here"', "tab")
    h.eq(json.encode("\1\2"), '"\\u0001\\u0002"', "raw control bytes")
  end)

  h.it("keeps multibyte content verbatim (8-bit clean)", function()
    -- UTF-8 for e-acute spelled with byte escapes: valid on every 5.x.
    h.eq(json.encode("caf\195\169"), '"caf\195\169"', "utf8 passthrough")
  end)

  h.it("encodes arrays without holes", function()
    h.eq(json.encode({}), "[]", "empty table is []")
    h.eq(json.encode({ 1, 2, 3 }), "[1,2,3]", "numbers")
    h.eq(json.encode({ "a", true }), '["a",true]', "mixed scalars")
    h.eq(json.encode({ { 1 }, { 2 } }), "[[1],[2]]", "nested arrays")
  end)

  h.it("encodes objects with sorted keys", function()
    h.eq(json.encode({ b = 1, a = 2 }), '{"a":2,"b":1}', "sorted keys")
    h.eq(json.encode({ name = "pw", bits = 40 }), '{"bits":40,"name":"pw"}',
      "mixed types sorted")
  end)

  h.it("skips nil-valued object entries", function()
    h.eq(json.encode({ a = 1, b = nil }), '{"a":1}', "nil value dropped")
  end)

  h.it("renders nested structures compactly", function()
    local payload = {
      command = "gen",
      passwords = { "alpha", "beta" },
      meta = { score = 4, ok = true },
    }
    h.eq(json.encode(payload),
      '{"command":"gen","meta":{"ok":true,"score":4},"passwords":["alpha","beta"]}',
      "compact form")
  end)

  h.it("pretty-prints with two-space indent and newlines", function()
    h.eq(json.encode_pretty({ a = 1 }),
      '{\n  "a": 1\n}', "single key object")
    h.eq(json.encode_pretty({ 1, 2 }),
      "[\n  1,\n  2\n]", "array rows")
    local nested = json.encode_pretty({ outer = { inner = { 1 } } })
    h.match(nested, '"outer": {\n', "nested object line")
    h.match(nested, '    "inner"', "deep indentation")
  end)

  h.it("empty containers stay on one line even when pretty", function()
    h.eq(json.encode_pretty({ list = {}, map = {} }),
      '{\n  "list": [],\n  "map": {}\n}', "empty join path")
  end)

  h.it("stringifies non-string object keys deterministically", function()
    h.eq(json.encode({ [10] = "x" }), '{"10":"x"}', "number key")
    h.eq(json.encode({ [true] = 1 }), '{"true":1}', "boolean key")
  end)

  h.it("rejects unencodable values with a namespaced error", function()
    h.raises(function() json.encode({ 0 / 0 }) end,
      "passforge.json:", "NaN inside array")
    h.raises(function() json.encode(math.huge) end,
      "passforge.json:", "infinity")
    h.raises(function() json.encode({ f = print }) end,
      "passforge.json:", "function value")
  end)

  h.it("survives deep-but-legal nesting", function()
    local deep = { ok = true }
    local node = deep
    for _ = 1, 50 do
      local next_node = { child = {} }
      node.child[1] = next_node
      node = next_node
    end
    local encoded = json.encode(deep)
    h.match(encoded, '^{"child":%[', "deep chain starts as object")
    h.true_(#encoded > 400, "depth present in output")
  end)

  h.it("rejects nesting beyond the 64-level guard", function()
    local node = {}
    local root = node
    for _ = 1, 70 do
      local next_node = {}
      node[1] = next_node
      node = next_node
    end
    h.raises(function() json.encode(root) end,
      "passforge.json:", "depth guard")
  end)

  h.it("round-trips a typical CLI payload shape", function()
    local payload = {
      command = "pass",
      count = 2,
      passphrases = { "alpha-beta-gamma-delta", "echo-falcon-golf-hotel" },
      entropy_bits = 40.0,
      parameters = { words = 4, capitalize = false, append_digit = false },
    }
    local wire = json.encode(payload)
    h.match(wire, '"entropy_bits":40}', "40.0 renders as 40")
    h.match(wire, '"passphrases":%["alpha%-beta%-gamma%-delta"', "array member")
    h.true_(wire:sub(1, 1) == "{", "object at top level")
  end)

  h.it("compat.fail errors carry through unchanged", function()
    local err = h.raises(function()
      compat.fail("json", "synthetic")
    end, "passforge.json:", "protocol")
    h.eq(err, "passforge.json: synthetic", "exact message")
  end)

end)
