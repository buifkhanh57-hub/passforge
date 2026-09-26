--- passforge/cli.lua
-- The passforge command line interface.
--
-- COMMANDS
--   gen        random passwords from character sets
--   pass       passphrase from the embedded 1024-word list
--   strength   analyze a single password
--   audit      audit a batch (files or stdin), CI-friendly exit code
--   entropy    show the math for a generation mode without generating
--   tips       contextual recommendations (password or generation options)
--   hash       SHA-256 of an argument, a file, or stdin
--   charset    print the character-set tables the toolkit uses
--   selftest   run the embedded spec suite (spec/run.lua)
--   version    identity + active bitwise backend
--   help       usage for everything or one command
--
-- GLOBAL FLAGS
--   --json      machine-readable output (compact)
--   --pretty    machine-readable output, indented (implies --json)
--   --version   same as the `version` command
--
-- EXIT CODES
--   0  success
--   1  audit finished but at least one password scored below --min-score
--   2  usage error (unknown command/option, missing value, unreadable input)
--   3  runtime error (a passforge.<module> message from deeper in the stack)
--
-- DESIGN NOTES
--   * Every subcommand accepts its options in GNU style: --opt, --opt=v,
--     --opt v, and one-letter shorts with or without an attached value.
--   * "-" as a positional means stdin (password text for strength/tips,
--     one password per line for audit, raw bytes for hash).
--   * Nothing writes secrets to stderr; reports mask them by default.

local compat    = require("passforge.compat")
local charsets  = require("passforge.charsets")
local generator = require("passforge.generator")
local passphrase = require("passforge.passphrase")
local random    = require("passforge.random")
local sha256    = require("passforge.sha256")
local strength  = require("passforge.strength")
local audit     = require("passforge.audit")
local tips      = require("passforge.tips")
local entropy   = require("passforge.entropy")
local json      = require("passforge.json")
local version   = require("passforge.version")

local M = {}

-- ---------------------------------------------------------------------------
-- Small output / parsing helpers
-- ---------------------------------------------------------------------------

local function out(text)
  io.write(text .. "\n")
end

local function read_stdin_all()
  local data = io.read("*a")
  if type(data) ~= "string" then
    return ""
  end
  return data
end

local function trim_trailing_newlines(s)
  return (s:gsub("[\r\n]+$", ""))
end

--- Raise a usage-classified error: caught by M.run and mapped to exit 2.
local function usage_fail(where, fmt, ...)
  error("@usage: " .. string.format("[%s] " .. fmt, where, ...), 0)
end

local function emit_json(opts, payload)
  if opts.pretty then
    out(json.encode_pretty(payload))
  else
    out(json.encode(payload))
  end
end

--- Parse "--flag=v / --flag v / -f v / -fv" plus bare positionals.
-- spec maps long name -> { short = "l", value = true|false }.
-- Returns params (keyed by LONG name) and the positional array.
local function parse_flags(args, spec, where)
  local params, positional = {}, {}
  local function find_def(name)
    if spec[name] then
      return name, spec[name]
    end
    for long, def in pairs(spec) do
      if def.short == name then
        return long, def
      end
    end
    return nil, nil
  end

  local i = 1
  while i <= #args do
    local a = args[i]
    if a == "--" then
      for j = i + 1, #args do
        positional[#positional + 1] = args[j]
      end
      break
    elseif a == "-" then
      positional[#positional + 1] = a
      i = i + 1
    elseif a:sub(1, 2) == "--" then
      local body = a:sub(3)
      local eq = body:find("=", 1, true)
      local name, inline
      if eq then
        name = body:sub(1, eq - 1)
        inline = body:sub(eq + 1)
      else
        name = body
      end
      local long, def = find_def(name)
      if not def then
        usage_fail(where, "unknown option '--%s'", name)
      end
      local value
      if def.value then
        if inline ~= nil then
          value = inline
        elseif i < #args then
          i = i + 1
          value = args[i]
        else
          usage_fail(where, "option '--%s' expects a value", name)
        end
      else
        if inline ~= nil then
          usage_fail(where, "option '--%s' takes no value", name)
        end
        value = true
      end
      params[long] = value
      i = i + 1
    elseif a:sub(1, 1) == "-" and #a >= 2 then
      local body = a:sub(2)
      local short = body:sub(1, 1)
      local long, def = find_def(short)
      if not def then
        usage_fail(where, "unknown option '-%s'", short)
      end
      local value
      if def.value then
        if #body > 1 then
          value = body:sub(2)
        elseif i < #args then
          i = i + 1
          value = args[i]
        else
          usage_fail(where, "option '-%s' expects a value", short)
        end
      else
        value = true
      end
      params[long] = value
      i = i + 1
    else
      positional[#positional + 1] = a
      i = i + 1
    end
  end
  return params, positional
end

--- Coerce a flag value to an integer in [lo, hi] or raise a usage error.
local function to_int(value, label, where, lo, hi)
  local n = tonumber(value)
  if not n or math.floor(n) ~= n then
    usage_fail(where, "%s expects an integer, got '%s'", label, tostring(value))
  end
  n = math.floor(n)
  if lo and n < lo then
    usage_fail(where, "%s must be >= %d, got %d", label, lo, n)
  end
  if hi and n > hi then
    usage_fail(where, "%s must be <= %d, got %d", label, hi, n)
  end
  return n
end

-- ---------------------------------------------------------------------------
-- Command handlers
-- ---------------------------------------------------------------------------

local function cmd_gen(args, opts)
  local params, _ = parse_flags(args, {
    length            = { short = "l", value = true },
    count             = { short = "c", value = true },
    sets              = { short = "s", value = true },
    ["no-ambiguous"]  = { value = false },
    ["no-repeats"]    = { value = false },
    ["no-require-each"] = { value = false },
    seed              = { value = true },
  }, "gen")

  local gen_opts = {}
  gen_opts.length = params.length
    and to_int(params.length, "--length", "gen",
      generator.LIMITS.min_length, generator.LIMITS.max_length)
    or generator.LIMITS.default_length
  gen_opts.sets = params.sets
  gen_opts.exclude_ambiguous = params["no-ambiguous"] and true or false
  gen_opts.no_repeats = params["no-repeats"] and true or false
  gen_opts.must_include_each = not (params["no-require-each"] and true)
  if params.seed then
    gen_opts.rng = random.new(params.seed)
    gen_opts.seed = params.seed
  end

  local count = params.count
    and to_int(params.count, "--count", "gen", 1, generator.LIMITS.max_count)
    or 1

  local est = entropy.estimate_generate(gen_opts)
  local list
  if count == 1 then
    list = { generator.generate(gen_opts) }
  else
    list = generator.generate_many(gen_opts)
  end

  if opts.json then
    emit_json(opts, {
      command = "gen",
      passwords = list,
      count = count,
      parameters = {
        length = gen_opts.length,
        sets = gen_opts.sets,
        pool_size = est.pool_size,
        exclude_ambiguous = gen_opts.exclude_ambiguous,
        no_repeats = gen_opts.no_repeats,
        must_include_each = gen_opts.must_include_each,
        deterministic = gen_opts.seed ~= nil,
      },
      entropy_bits = est.entropy_bits,
      verdict = est.verdict,
      score = est.score,
    })
  else
    for i = 1, #list do
      out(list[i])
    end
  end
  return 0
end

local function cmd_pass(args, opts)
  local params, _ = parse_flags(args, {
    words    = { short = "w", value = true },
    count    = { short = "c", value = true },
    sep      = { value = true },
    cap      = { value = false },
    digit    = { value = false },
    seed     = { value = true },
  }, "pass")

  local pass_opts = {}
  pass_opts.words = params.words
    and to_int(params.words, "--words", "pass",
      passphrase.LIMITS.min_words, passphrase.LIMITS.max_words)
    or passphrase.LIMITS.default_words
  if params.sep then
    local sep = params.sep
    if #sep < 1 or #sep > 3 or sep:find("%s") then
      usage_fail("pass", "--sep must be 1-3 characters without whitespace")
    end
    pass_opts.separator = sep
  end
  pass_opts.capitalize = params.cap and true or false
  pass_opts.append_digit = params.digit and true or false
  if params.seed then
    pass_opts.rng = random.new(params.seed)
    pass_opts.seed = params.seed
  end

  local count = params.count
    and to_int(params.count, "--count", "pass", 1, 1000)
    or 1

  local est = entropy.estimate_passphrase(pass_opts)
  local list
  if count == 1 then
    list = { passphrase.build(pass_opts) }
  else
    list = passphrase.generate_many(pass_opts)
  end

  if opts.json then
    emit_json(opts, {
      command = "pass",
      passphrases = list,
      count = count,
      parameters = {
        words = pass_opts.words,
        separator = pass_opts.separator or "-",
        capitalize = pass_opts.capitalize,
        append_digit = pass_opts.append_digit,
        wordlist_size = est.wordlist_size,
        deterministic = pass_opts.seed ~= nil,
      },
      entropy_bits = est.entropy_bits,
      bits_per_word = est.bits_per_word,
      combinations = est.combinations,
      verdict = est.verdict,
      score = est.score,
    })
  else
    for i = 1, #list do
      out(list[i])
    end
  end
  return 0
end

local function render_strength(report)
  out(string.format("verdict:   %s (score %d/5)", report.verdict, report.score))
  out(string.format("entropy:   %.2f bits  (base %.2f - deductions %.2f)",
    report.entropy_bits, report.base_bits, report.deductions))
  out(string.format("length:    %d   classes: %s   pool: %d",
    report.length, report.classes, report.pool_size))
  out(string.format("views:     pool %.2f | distinct %.2f | shannon %.2f bits",
    report.pool_bits, report.unique_bits, report.shannon_bits))
  if report.is_common then
    out(string.format("ALERT:     found on the embedded common-password corpus (rank #%d)",
      report.common_rank or 0))
  end
  if #report.findings == 0 then
    out("findings:  none")
  else
    out(string.format("findings:  %d", #report.findings))
    for i = 1, #report.findings do
      local f = report.findings[i]
      out(string.format("  [%s] %s (-%.2f bits)", f.severity, f.title, f.penalty))
      out("          " .. f.detail)
    end
  end
  out("crack time (average case, half the keyspace):")
  for i = 1, #report.crack do
    local c = report.crack[i]
    out(string.format("  %-36s %s", c.label, c.human))
  end
  if #report.tips > 0 then
    out("suggestions:")
    for i = 1, #report.tips do
      local t = report.tips[i]
      out("  " .. tips.format_tip(t))
      out("    " .. t.how)
    end
  end
end

local function cmd_strength(args, opts)
  local params, positional = parse_flags(args, {}, "strength")
  if params and next(params) then
    usage_fail("strength", "this command takes no options beyond --json/--pretty")
  end

  local pw = positional[1]
  if not pw or pw == "-" then
    pw = trim_trailing_newlines(read_stdin_all())
    if pw == "" then
      usage_fail("strength",
        "no password provided (pass one as an argument or pipe it in)")
    end
  end

  local report = strength.analyze(pw)
  report.command = "strength"
  report.tips = tips.for_analysis(report)

  if opts.json then
    emit_json(opts, report)
  else
    render_strength(report)
  end
  return 0
end

local function read_password_lines(path)
  local data
  if path then
    local fh, open_err = io.open(path, "r")
    if not fh then
      usage_fail("audit", "cannot open file '%s': %s", path, tostring(open_err))
    end
    data = fh:read("*a")
    fh:close()
  else
    data = read_stdin_all()
  end
  local list = {}
  for line in (data .. "\n"):gmatch("([^\r\n]*)\r?\n") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if line ~= "" and line:sub(1, 1) ~= "#" then
      list[#list + 1] = line
    end
  end
  return list
end

local function cmd_audit(args, opts)
  local params, positional = parse_flags(args, {
    ["min-score"] = { short = "m", value = true },
    reveal        = { value = false },
    ["no-tips"]   = { value = false },
  }, "audit")

  local threshold
  if params["min-score"] then
    threshold = to_int(params["min-score"], "--min-score", "audit", 0, 5)
  end

  local passwords
  if #positional == 0 or positional[1] == "-" then
    passwords = read_password_lines(nil)
  else
    passwords = {}
    for i = 1, #positional do
      local chunk = read_password_lines(positional[i])
      for j = 1, #chunk do
        passwords[#passwords + 1] = chunk[j]
      end
    end
  end
  if #passwords == 0 then
    usage_fail("audit", "no passwords found (pass files or pipe one-per-line on stdin)")
  end

  local batch = audit.audit_many(passwords, {
    reveal = params.reveal and true or false,
    no_tips = params["no-tips"] and true or false,
  })
  batch.command = "audit"
  if threshold then
    batch.threshold = threshold
    batch.fails_threshold = audit.fails_threshold(batch, threshold)
  end

  if opts.json then
    emit_json(opts, batch)
  else
    for i = 1, #batch.results do
      local r = batch.results[i]
      out(string.format("%3d. %-10s %7.2f bits  score %d/5  %-14s %d finding%s",
        i, r.verdict, r.entropy_bits, r.score, r.password_masked,
        #r.findings, #r.findings == 1 and "" or "s"))
    end
    out("")
    out(audit.batch_summary_line(batch))
    if threshold then
      if batch.fails_threshold then
        out(string.format("THRESHOLD: FAIL - at least one password scores below %d/5", threshold))
      else
        out(string.format("THRESHOLD: PASS - every password scores %d/5 or better", threshold))
      end
    end
  end

  if threshold and batch.fails_threshold then
    return 1
  end
  return 0
end

local function cmd_entropy(args, opts)
  local params, _ = parse_flags(args, {
    mode             = { short = "m", value = true },
    length           = { short = "l", value = true },
    sets             = { short = "s", value = true },
    words            = { short = "w", value = true },
    ["no-ambiguous"] = { value = false },
    cap              = { value = false },
    digit            = { value = false },
  }, "entropy")

  local mode = params.mode or "gen"
  if mode ~= "gen" and mode ~= "pass" then
    usage_fail("entropy", "--mode must be 'gen' or 'pass', got '%s'", mode)
  end

  local est
  if mode == "gen" then
    local gen_opts = {}
    gen_opts.length = params.length
      and to_int(params.length, "--length", "entropy",
        generator.LIMITS.min_length, generator.LIMITS.max_length)
      or generator.LIMITS.default_length
    gen_opts.sets = params.sets
    gen_opts.exclude_ambiguous = params["no-ambiguous"] and true or false
    est = entropy.estimate_generate(gen_opts)
    est.sets = gen_opts.sets
    est.exclude_ambiguous = gen_opts.exclude_ambiguous
  else
    local pass_opts = {}
    pass_opts.words = params.words
      and to_int(params.words, "--words", "entropy",
        passphrase.LIMITS.min_words, passphrase.LIMITS.max_words)
      or passphrase.LIMITS.default_words
    pass_opts.capitalize = params.cap and true or false
    pass_opts.append_digit = params.digit and true or false
    est = entropy.estimate_passphrase(pass_opts)
  end
  est.command = "entropy"
  est.tips = tips.for_estimate(est)

  if opts.json then
    emit_json(opts, est)
  else
    out(string.format("mode:      %s", mode))
    if mode == "gen" then
      out(string.format("pool:      %d characters (%s)",
        est.pool_size, est.description))
    else
      out(string.format("words:     %d from a %d-word list (%.2f bits/word)",
        est.words, est.wordlist_size, est.bits_per_word))
    end
    out(string.format("entropy:   %.2f bits  ->  %s (score %d/5)",
      est.entropy_bits, est.verdict, est.score))
    out(string.format("keyspace:  %s combinations", est.combinations))
    out("crack time (average case, half the keyspace):")
    for i = 1, #est.crack do
      local c = est.crack[i]
      out(string.format("  %-36s %s", c.label, c.human))
    end
    if #est.tips > 0 then
      out("suggestions:")
      for i = 1, #est.tips do
        out("  " .. tips.format_tip(est.tips[i]))
      end
    end
  end
  return 0
end

local function cmd_tips(args, opts)
  local params, positional = parse_flags(args, {
    mode    = { short = "m", value = true },
    length  = { short = "l", value = true },
    sets    = { short = "s", value = true },
    words   = { short = "w", value = true },
    cap     = { value = false },
    digit   = { value = false },
    seed    = { value = true },
    ["no-ambiguous"] = { value = false },
    ["no-repeats"]   = { value = false },
    ["no-require-each"] = { value = false },
  }, "tips")

  local payload = { command = "tips" }
  if positional[1] and positional[1] ~= "-" then
    local report = strength.analyze(positional[1])
    payload.source = "password"
    payload.verdict = report.verdict
    payload.entropy_bits = report.entropy_bits
    payload.tips = tips.for_analysis(report)
  elseif positional[1] == "-" or not params.mode then
    local pw = trim_trailing_newlines(read_stdin_all())
    if pw == "" then
      usage_fail("tips", "give a password argument, '-' for stdin, or --mode gen|pass")
    end
    local report = strength.analyze(pw)
    payload.source = "stdin"
    payload.verdict = report.verdict
    payload.entropy_bits = report.entropy_bits
    payload.tips = tips.for_analysis(report)
  else
    local mode = params.mode
    if mode ~= "gen" and mode ~= "pass" then
      usage_fail("tips", "--mode must be 'gen' or 'pass', got '%s'", mode)
    end
    local o = {}
    if mode == "gen" then
      o.length = params.length
        and to_int(params.length, "--length", "tips", 4, generator.LIMITS.max_length)
        or generator.LIMITS.default_length
      o.sets = params.sets
      o.exclude_ambiguous = params["no-ambiguous"] and true or false
      o.no_repeats = params["no-repeats"] and true or false
      o.must_include_each = not (params["no-require-each"] and true)
    else
      o.words = params.words
        and to_int(params.words, "--words", "tips", 3, passphrase.LIMITS.max_words)
        or passphrase.LIMITS.default_words
      o.capitalize = params.cap and true or false
      o.append_digit = params.digit and true or false
    end
    o.seed = params.seed
    payload.source = "mode:" .. mode
    payload.tips = tips.for_generation(mode, o)
  end

  if opts.json then
    emit_json(opts, payload)
  else
    out(string.format("context:   %s", payload.source or "unknown"))
    if payload.verdict then
      out(string.format("verdict:   %s (%.2f bits)", payload.verdict, payload.entropy_bits))
    end
    out(string.format("tips:      %d", #payload.tips))
    for i = 1, #payload.tips do
      local t = payload.tips[i]
      out(string.format("  %d. [%s] %s", i, t.severity, t.title))
      out("     why: " .. t.why)
      out("     how: " .. t.how)
    end
  end
  return 0
end

local function cmd_hash(args, opts)
  local params, positional = parse_flags(args, {
    file = { short = "f", value = true },
  }, "hash")

  local digest, source
  if params.file then
    local fh, open_err = io.open(params.file, "rb")
    if not fh then
      usage_fail("hash", "cannot open file '%s': %s", params.file, tostring(open_err))
    end
    fh:close()
    digest = sha256.hexdigest_file(params.file)
    source = "file:" .. params.file
  else
    local data = positional[1]
    source = "argument"
    if not data or data == "-" then
      data = read_stdin_all()
      source = "stdin"
      -- stdin convenience: a trailing newline from echo(1) would otherwise
      -- change the digest; strip exactly one trailing CR/LF run.
      data = trim_trailing_newlines(data)
    end
    if data == "" then
      usage_fail("hash", "nothing to hash (pass a string, a file with --file, or pipe data)")
    end
    digest = sha256.hex(data)
  end

  if opts.json then
    emit_json(opts, {
      command = "hash",
      algorithm = "sha256",
      input = source,
      bytes = 32,
      hex = digest,
    })
  else
    out(digest)
  end
  return 0
end

local function cmd_charset(args, opts)
  local params, _ = parse_flags(args, {}, "charset")
  if params and next(params) then
    usage_fail("charset", "this command takes no options beyond --json/--pretty")
  end

  local sets = {}
  for _, name in ipairs(charsets.order()) do
    local chars = charsets.SETS[name]
    sets[name] = {
      size = #chars,
      without_ambiguous = #charsets.remove_ambiguous(chars),
      chars = chars,
    }
  end
  local payload = {
    command = "charset",
    sets = sets,
    aliases = charsets.ALIASES,
    class_sizes = charsets.CLASS_SIZE,
    pool_reference = entropy.pool_reference(),
  }

  if opts.json then
    emit_json(opts, payload)
  else
    out("canonical character sets (charset.lua is the single source of truth):")
    for _, name in ipairs(charsets.order()) do
      local s = sets[name]
      out(string.format("  %-8s %3d characters  (%d without Il1O0o|)  %s",
        name, s.size, s.without_ambiguous, s.chars))
    end
    out(string.format("aliases:  -s luds maps l=lower u=upper d=digits s=symbols"))
    out(string.format("pools:    lower+upper+digits = 62   all printable = 94"))
  end
  return 0
end

local function cmd_selftest(args, opts)
  local params, _ = parse_flags(args, {}, "selftest")
  if params and next(params) then
    usage_fail("selftest", "this command takes no options")
  end
  local ok, runner = pcall(require, "spec.run")
  if not ok then
    compat.fail("cli", "selftest needs the spec suite (spec/run.lua) on the package path")
  end
  return runner.run_all()
end

local function cmd_version(_args, opts)
  local payload = {
    command = "version",
    name = version.name,
    version = version.version,
    codename = version.codename,
    description = version.description,
    author = version.author,
    license = version.license,
    homepage = version.homepage,
    lua_target = version.lua_target,
    interpreter = _VERSION,
    bitwise_backend = compat.backend(),
  }
  if opts.json then
    emit_json(opts, payload)
  else
    out(string.format("%s %s (%s) - %s", payload.name, payload.version,
      payload.codename, payload.description))
    out(string.format("lua %s on %s, bitwise backend: %s",
      version.lua_target, payload.interpreter, payload.bitwise_backend))
    out(string.format("license %s, author %s", payload.license, payload.author))
  end
  return 0
end

local function cmd_help(args, _opts)
  if #args == 0 then
    out(M.USAGE)
    return 0
  end
  local name = args[1]
  local def = M.COMMANDS[name]
  if not def then
    for key, d in pairs(M.COMMANDS) do
      for al = 1, #(d.aliases or {}) do
        if d.aliases[al] == name then
          def = d
          name = key
        end
      end
    end
  end
  if not def then
    usage_fail("help", "unknown command '%s'", tostring(args[1]))
  end
  out(def.help)
  return 0
end

-- ---------------------------------------------------------------------------
-- Registry, usage text, dispatch
-- ---------------------------------------------------------------------------

M.COMMANDS = {
  gen = {
    summary = "generate random passwords from character sets",
    aliases = { "generate", "rand" },
    help = [[
gen - generate random passwords

usage: passforge gen [options]

  -l, --length N        password length (4-256, default 16)
  -c, --count N         how many DISTINCT passwords (1-1000, default 1)
  -s, --sets SPEC       character sets: l=lower u=upper d=digits s=symbols,
                        e.g. "luds"; default "lud"
      --no-ambiguous    strip Il1O0o| from every set
      --no-repeats      sample without replacement
      --no-require-each do not force one character per selected set
      --seed TEXT       deterministic mode (TESTS ONLY - see tips)
      --json            machine-readable output

examples:
  passforge gen --length 20 --sets luds
  passforge gen --count 5 --no-ambiguous --json]],
  },
  pass = {
    summary = "generate passphrases from the embedded wordlist",
    aliases = { "passphrase" },
    help = [[
pass - generate passphrases from the embedded 1024-word list

usage: passforge pass [options]

  -w, --words N         word count (3-24, default 4; 10.00 bits each)
  -c, --count N         how many DISTINCT passphrases (default 1)
      --sep TEXT        separator, 1-3 chars, no whitespace (default "-")
      --cap             capitalize the first letter of every word
      --digit           append one random digit (~3.32 extra bits)
      --seed TEXT       deterministic mode (TESTS ONLY)
      --json            machine-readable output

examples:
  passforge pass --words 5
  passforge pass --words 6 --sep . --cap --json]],
  },
  strength = {
    summary = "analyze one password (argument or stdin)",
    aliases = { "check" },
    help = [[
strength - analyze a single password

usage: passforge strength PASSWORD
       echo 'PASSWORD' | passforge strength -

Prints verdict, entropy decomposition, findings, crack times and tips.
Use "-" (or no argument) to read the password from stdin.
The password itself is never written back in --json output beyond the
input you already exposed on the command line.

examples:
  passforge strength ' hunter2 '
  passforge gen --length 16 | passforge strength -]],
  },
  audit = {
    summary = "audit a batch of passwords (files or stdin)",
    aliases = {},
    help = [[
audit - audit many passwords at once

usage: passforge audit [FILE...|-] [options]

Reads one password per line; empty lines and lines starting with '#'
are ignored. With no file (or "-") it reads stdin.

  -m, --min-score N     exit 1 when any password scores below N (0-5)
      --reveal          include plaintext in reports (default: masked)
      --no-tips         skip the recommendation pass
      --json            machine-readable output (batch + summary)

Exit codes: 0 ok, 1 threshold failed, 2 usage, 3 runtime.

examples:
  passforge audit passwords.txt --min-score 3
  printf 'hunter2\nTr0ub4dor&3\n' | passforge audit --json]],
  },
  entropy = {
    summary = "show entropy math for a generation mode",
    aliases = { "est" },
    help = [[
entropy - show the entropy math without generating anything

usage: passforge entropy [--mode gen|pass] [options]

  -m, --mode MODE       "gen" (default) or "pass"
  gen:  -l, --length N; -s, --sets SPEC; --no-ambiguous
  pass: -w, --words N; --cap; --digit
      --json            machine-readable output

Reports pool/wordlist sizes, bits, keyspace, verdict and average crack
times at five documented attacker rates.

examples:
  passforge entropy --mode gen --length 20 --sets luds
  passforge entropy --mode pass --words 6 --json]],
  },
  tips = {
    summary = "contextual recommendations for a password or settings",
    aliases = { "advise" },
    help = [[
tips - contextual recommendations

usage: passforge tips PASSWORD|- [options]
       passforge tips --mode gen [gen options]
       passforge tips --mode pass [pass options]

With a password argument (or "-" for stdin) the tips come from the
strength analysis; with --mode they come from the generation settings.
Accepts the same per-mode options as gen/pass (--length, --sets,
--words, --cap, --digit, --seed, --no-ambiguous, --no-repeats).

examples:
  passforge tips 'Summer2023!'
  passforge tips --mode pass --words 4 --digit --json]],
  },
  hash = {
    summary = "SHA-256 of an argument, file, or stdin",
    aliases = { "sha256" },
    help = [[
hash - SHA-256 via the embedded FIPS 180-4 implementation

usage: passforge hash STRING
       passforge hash --file PATH
       cat FILE | passforge hash -

  -f, --file PATH       hash the file in 64 KiB chunks
      --json            machine-readable output

stdin input has its trailing newline stripped (so `echo abc |` matches
the canonical "abc" vector); arguments are used byte-exact.

examples:
  passforge hash abc
  passforge hash --file /etc/hostname --json]],
  },
  charset = {
    summary = "print the character-set tables",
    aliases = { "charsets" },
    help = [[
charset - print character sets, sizes and ambiguity filtering

usage: passforge charset [--json]

Shows the four canonical sets, their sizes with and without the
ambiguous characters Il1O0o|, the alias letters, and the reference
pool sizes entropy.lua uses.]],
  },
  selftest = {
    summary = "run the embedded spec suite",
    aliases = { "test" },
    help = [[
selftest - run the embedded spec suite

usage: passforge selftest

Requires spec/ to be reachable from the package path (it ships with
the repository). Exits non-zero on the first failing assertion batch
after printing the summary.]],
  },
  version = {
    summary = "print identity, interpreter and backend",
    aliases = {},
    help = [[
version - print passforge identity and environment

usage: passforge version [--json]

Shows the version table from passforge/version.lua plus the running
interpreter (_VERSION) and the active bitwise backend (bit32, bit, or
pure-Lua fallback).]],
  },
  help = {
    summary = "show usage (all commands or one)",
    aliases = {},
    help = [[
help - show usage

usage: passforge help          (everything)
       passforge help COMMAND  (one command)]],
  },
}

local function build_usage()
  local lines = {}
  lines[#lines + 1] = "passforge " .. version.version ..
    " (" .. version.codename .. ") - " .. version.description
  lines[#lines + 1] = ""
  lines[#lines + 1] = "usage: passforge COMMAND [options]"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "commands:"
  local names = {}
  for name in pairs(M.COMMANDS) do
    names[#names + 1] = name
  end
  table.sort(names)
  for i = 1, #names do
    local name = names[i]
    local def = M.COMMANDS[name]
    local alias = ""
    if #def.aliases > 0 then
      alias = "  (alias: " .. table.concat(def.aliases, ", ") .. ")"
    end
    lines[#lines + 1] = string.format("  %-9s %s%s", name, def.summary, alias)
  end
  lines[#lines + 1] = ""
  lines[#lines + 1] = "global flags:  --json   compact machine-readable output"
  lines[#lines + 1] = "               --pretty indented machine-readable output (implies --json)"
  lines[#lines + 1] = "               --version identity banner"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "exit codes:    0 ok   1 audit threshold failed   2 usage   3 runtime"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "run 'passforge help COMMAND' for per-command details."
  lines[#lines + 1] = "documentation: passforge/README.md (entropy model, security notes, FAQ)"
  return table.concat(lines, "\n")
end

M.USAGE = build_usage()

local function resolve_command(name)
  local def = M.COMMANDS[name]
  if def then
    return name, def
  end
  for key, d in pairs(M.COMMANDS) do
    for al = 1, #(d.aliases or {}) do
      if d.aliases[al] == name then
        return key, d
      end
    end
  end
  return nil, nil
end

local function dispatch(argv)
  local global = { json = false, pretty = false }
  local rest = {}
  local i = 1
  while i <= #argv do
    local a = argv[i]
    if a == "--" then
      i = i + 1
      while i <= #argv do
        rest[#rest + 1] = argv[i]
        i = i + 1
      end
      break
    elseif a == "--json" then
      global.json = true
      i = i + 1
    elseif a == "--pretty" then
      global.json = true
      global.pretty = true
      i = i + 1
    elseif a == "--version" then
      return cmd_version({}, global)
    else
      rest[#rest + 1] = a
      i = i + 1
    end
  end

  if #rest == 0 then
    out(M.USAGE)
    return 0
  end

  local name = table.remove(rest, 1)
  if name == "help" then
    return cmd_help(rest, global)
  end
  local key, def = resolve_command(name)
  if not def then
    usage_fail("cli", "unknown command '%s' (try 'passforge help')", name)
  end
  return def.handler(rest, global)
end

--- Run the CLI. Returns the process exit code:
--   0 ok | 1 audit threshold | 2 usage | 3 runtime.
-- Runtime errors carry the "passforge.<module>:" prefix from compat.fail();
-- usage errors carry an internal "@usage: " marker and print a help hint.
function M.run(argv)
  if argv == nil then
    argv = {}
  end
  local ok, result = pcall(dispatch, argv)
  if ok then
    return result
  end
  local msg = tostring(result)
  if msg:sub(1, 8) == "@usage: " then
    io.stderr:write("passforge: " .. msg:sub(9) .. "\n")
    io.stderr:write("run 'passforge help' for usage.\n")
    return 2
  end
  io.stderr:write("passforge: error: " .. msg .. "\n")
  return 3
end

return M
