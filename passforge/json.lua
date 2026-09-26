--- passforge/json.lua
-- Minimal dependency-free JSON *encoder* (output only).
--
-- Scope: passforge only ever WRITES JSON (for --json flags), it never parses
-- it. So this module implements exactly what that needs: nil/boolean/
-- number/string/table with deterministic key order, proper string escaping
-- and pretty-printing. Unsupported types raise a passforge error instead of
-- silently producing invalid JSON.
--
-- Table rules:
--   * a table is encoded as an ARRAY when it has no holes and #t covers
--     every key it contains; an EMPTY table encodes as [];
--   * everything else (including mixed tables) is encoded as an OBJECT with
--     keys sorted by tostring() for byte-identical output across runs;
--   * nil-valued object entries are skipped (arrays must not contain holes).

local compat = require("passforge.compat")

local M = {}

local function escape_string(s)
  -- Order matters: backslash first so later insertions are not themselves
  -- re-escaped. Control characters (including \n, \t) become \u00XX, which
  -- is always valid JSON even when the specific short form is unknown.
  s = s:gsub("\\", "\\\\")
  s = s:gsub('"', '\\"')
  s = s:gsub("%c", function(c)
    return string.format("\\u%04x", c:byte())
  end)
  return '"' .. s .. '"'
end

local function encode_number(v)
  if v ~= v or v == math.huge or v == -math.huge then
    compat.fail("json", "cannot encode NaN or infinity")
  end
  -- Integral numbers (including 5.3/5.4 floats like 3.0) must not print as
  -- "3.0"; string.format("%d") would even raise on non-integer floats in
  -- 5.3+, so floor explicitly first.
  if v == math.floor(v) and math.abs(v) < 2 ^ 53 then
    return string.format("%d", math.floor(v))
  end
  return string.format("%.14g", v)
end

--- Decide array vs object. An empty table is an array ([]).
local function is_array(t)
  local n = #t
  local count = 0
  for _ in pairs(t) do
    count = count + 1
  end
  if count == 0 then
    return true
  end
  return count == n
end

local encode_value  -- forward declaration (recursion through tables)

local function join(open, close, parts, level, indent)
  if not indent or #parts == 0 then
    return open .. table.concat(parts, ",") .. close
  end
  local pad_in = string.rep(indent, level + 1)
  local pad_out = string.rep(indent, level)
  return open .. "\n" .. pad_in .. table.concat(parts, ",\n" .. pad_in)
       .. "\n" .. pad_out .. close
end

local function encode_table(t, indent, level)
  if level > 64 then
    compat.fail("json", "table nesting deeper than 64 levels")
  end
  local open, close
  if is_array(t) then
    open, close = "[", "]"
    local parts = {}
    for i = 1, #t do
      parts[i] = encode_value(t[i], indent, level + 1)
    end
    return join(open, close, parts, level, indent)
  end
  open, close = "{", "}"
  local keys = {}
  for k in pairs(t) do
    keys[#keys + 1] = k
  end
  table.sort(keys, function(a, b)
    return tostring(a) < tostring(b)
  end)
  local parts = {}
  for i = 1, #keys do
    local k = keys[i]
    local v = t[k]
    if v ~= nil then
      if type(k) ~= "string" then
        k = tostring(k)
      end
      parts[#parts + 1] = escape_string(k) .. ":" .. encode_value(v, indent, level + 1)
    end
  end
  return join(open, close, parts, level, indent)
end

encode_value = function(v, indent, level)
  local tv = type(v)
  if tv == "nil" then
    return "null"
  elseif tv == "boolean" then
    return tostring(v)
  elseif tv == "number" then
    return encode_number(v)
  elseif tv == "string" then
    return escape_string(v)
  elseif tv == "table" then
    return encode_table(v, indent, level)
  end
  compat.fail("json", "cannot encode value of type '%s'", tv)
end

--- Compact JSON: {"a":[1,2],"b":"x"} - one line, no spaces.
function M.encode(v)
  return encode_value(v, nil, 0)
end

--- Pretty JSON with two-space indentation, one element per line.
function M.encode_pretty(v)
  return encode_value(v, "  ", 0)
end

return M
