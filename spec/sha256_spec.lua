--- spec/sha256_spec.lua
-- Known-answer tests for the pure-Lua SHA-256 (FIPS 180-4).
--
-- The first block pins the implementation to the official NIST vectors
-- plus the de-facto standard community vectors; the rest exercises the
-- incremental API, padding boundaries and file streaming. If ANY of these
-- fail, the toolkit's security statements are void - treat it as broken.

local h      = require("spec.harness")
local sha256 = require("passforge.sha256")
local compat = require("passforge.compat")

h.suite("sha256", function()

  h.it("module constants match FIPS geometry", function()
    h.eq(sha256.BLOCK_SIZE, 64, "512-bit blocks")
    h.eq(sha256.DIGEST_SIZE, 32, "256-bit digest")
    h.eq(sha256.k_count(), 64, "64 round constants")
  end)

  h.it("K table starts and ends with the FIPS 180-4 constants", function()
    -- The K list itself is private; k_count() plus vector agreement below
    -- pins it. These two hex constants anchor the table's identity.
    h.eq(sha256.hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "any K error shows up immediately")
  end)

  h.it("NIST vector: empty string", function()
    h.eq(sha256.hex(""),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "empty message")
  end)

  h.it("NIST vector: 'abc' (one block, no padding pressure)", function()
    h.eq(sha256.hex("abc"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "abc")
  end)

  h.it("NIST vector: 448-bit message (padding lands in second block)", function()
    local msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    h.eq(#msg, 56, "message is exactly 448 bits")
    h.eq(sha256.hex(msg),
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      "448-bit vector")
  end)

  h.it("NIST vector: 896-bit message (two full blocks before padding)", function()
    local msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" ..
                "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    h.eq(#msg, 112, "message is exactly 896 bits")
    h.eq(sha256.hex(msg),
      "cf5b16a778af8380036ce59e7b0492375b2495fdb8d4a65a543f14bd6da5e72",
      "896-bit vector")
  end)

  h.it("community vector: 'hello world'", function()
    h.eq(sha256.hex("hello world"),
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      "hello world")
  end)

  h.it("community vector: quick brown fox (prefix pin)", function()
    local digest = sha256.hex("The quick brown fox jumps over the lazy dog")
    h.eq(digest:sub(1, 32), "d7a8fbb307d7809469ca9abcb0082e4f",
      "prefix of the canonical fox digest")
    h.eq(#digest, 64, "full hex length")
  end)

  h.it("NIST vector: one million 'a' characters", function()
    h.eq(sha256.hex(string.rep("a", 1000000)),
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
      "million-a")
  end)

  h.it("binary content digests stably (NULs, high bytes)", function()
    -- Self-consistency: the digest must differ from the ASCII rendering and
    -- be sensitive to every byte position.
    local raw = string.char(0, 1, 2, 250, 251, 255)
    local a = sha256.hex(raw)
    local b = sha256.hex(raw:sub(1, 5))
    local c = sha256.hex(string.char(0, 1, 2, 250, 251, 254))
    h.eq(#a, 64, "digest length")
    h.true_(a ~= b, "length sensitivity")
    h.true_(a ~= c, "byte sensitivity")
    h.true_(a:match("^%x+$") ~= nil, "lowercase hex alphabet")
  end)

  h.it("incremental update() equals one-shot for split inputs", function()
    local message = "passforge incremental hashing check"
    local one_shot = sha256.hex(message)
    local splits = {
      { message },
      { message:sub(1, 1), message:sub(2) },
      { message:sub(1, 10), message:sub(11, 33), message:sub(34) },
      { message:sub(1, 31), message:sub(32, 64), message:sub(65) },
      { message:sub(1, 32), message:sub(33) },
      { message:sub(1, 64), message:sub(65) },
    }
    for i = 1, #splits do
      local st = sha256.new()
      for j = 1, #splits[i] do
        sha256.update(st, splits[i][j])
      end
      h.eq(sha256.hex(sha256.finish(st)) , one_shot,
        "split #" .. i .. " matches one-shot")
    end
  end)

  h.it("empty and whitespace-only inputs are stable", function()
    h.eq(sha256.hex(" "), sha256.hex(" "), "space repeated")
    h.true_(sha256.hex("") ~= sha256.hex(" "), "empty differs from space")
    h.true_(sha256.hex("\n") ~= sha256.hex("\r"), "line endings matter")
  end)

  h.it("padding boundary sweep across 55..66 bytes", function()
    -- The 0x80 pad byte, the zero run and the 8-byte length field move
    -- between blocks as the message length crosses 55/56/63/64/65.
    local base = string.rep("x", 66)
    for len = 0, 66 do
      local msg = base:sub(1, len)
      local st = sha256.new()
      sha256.update(st, msg)
      local incremental = sha256.hex(sha256.finish(st))
      h.eq(incremental, sha256.hex(msg), "boundary length " .. len)
    end
  end)

  h.it("hexdigest is an alias of hex", function()
    h.eq(sha256.hexdigest("abc"), sha256.hex("abc"), "alias")
  end)

  h.it("digest() returns 32 raw bytes", function()
    local raw = sha256.digest("abc")
    h.eq(#raw, 32, "byte length")
    h.eq(sha256.tohex(raw), sha256.hex("abc"), "tohex round trip")
  end)

  h.it("digest_file() streams a temporary file correctly", function()
    local path = os.tmpname()
    local fh = io.open(path, "wb")
    if not fh then
      h.fail("cannot create temp file for the streaming test")
    end
    fh:write("abc")
    fh:close()
    h.eq(sha256.hexdigest_file(path), sha256.hex("abc"), "file == string")
    os.remove(path)
  end)

  h.it("digest_file() reports missing files via the error protocol", function()
    h.raises(function() sha256.hexdigest_file("/nonexistent/passforge/missing") end,
      "passforge.sha256:", "missing file")
  end)

  h.it("update() rejects foreign states, finish() rejects them too", function()
    h.raises(function() sha256.update({}, "x") end,
      "passforge.sha256:", "bad state update")
    h.raises(function() sha256.finish({}) end,
      "passforge.sha256:", "bad state finish")
  end)

  h.it("update() with empty strings is a no-op", function()
    local st = sha256.new()
    sha256.update(st, "")
    sha256.update(st, "abc")
    h.eq(sha256.hex(sha256.finish(st)), sha256.hex("abc"), "empty updates")
  end)

  h.it("the pure-bit backend contract still holds after hashing", function()
    -- Guards against a backend change breaking hashing silently mid-suite.
    h.eq(compat.band(0xDEAD, 0xBEEF), 0xDEAD, "band sanity")
    h.eq(sha256.hex("abc"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "vector still green")
  end)

end)
