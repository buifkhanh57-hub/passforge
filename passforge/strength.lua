--- passforge/strength.lua
-- Human-pattern strength analysis: the "auditor" half of passforge.
--
-- MODEL
--   Generation-side entropy (entropy.lua) says how hard a password WOULD be
--   to brute-force if its characters were independent draws from the charset
--   pool. Real humans are not random: they type "qwerty", append birth
--   years, leetify dictionary words. This module detects those patterns and
--   subtracts documented bit penalties from the generation-side estimate,
--   then reports:
--
--     findings[]  every detected weakness with severity + penalty
--     entropy     max(0, base_bits - sum(penalties)), further capped when
--                 the password (or its leetified form) is on the embedded
--                 common-password list
--     score       0..5 via the shared entropy.SCALE (same scale the CLI uses)
--     crack       average crack times at five documented guess rates
--
--   This is a heuristic analyzer in the spirit of zxcvbn's feedback step,
--   NOT a crack simulation: it cannot see server-side rate limiting, hash
--   cost or whether the password is unique. The README "Security notes"
--   section spells out the limitations.
--
-- EMBEDDED CORPUS
--   COMMON_RANK holds ~500 of the most frequently leaked passwords (public
--   breach-list knowledge). Rank 1 = most common. Exact matches (case
--   insensitive), leetified variants and common+suffix combinations are all
--   recognised and heavily capped, because an attacker tries this list
--   first - checking it costs seconds, not centuries.

local compat   = require("passforge.compat")
local charsets = require("passforge.charsets")
local entropy  = require("passforge.entropy")
local wordlist = require("passforge.wordlist")

local M = {}

-- ---------------------------------------------------------------------------
-- Tunable penalties (bits), kept in one table so the README and the specs
-- can quote them exactly.
-- ---------------------------------------------------------------------------

M.PENALTY = {
  sequence_per_char  = 2.0,   -- per char of a 3+ alphabetical/numeric run
  repeat_per_char    = 1.5,   -- per char of a 3+ same-char or 2-cycle run
  keyboard_per_char  = 2.5,   -- per char of a 3+ keyboard-row walk
  year               = 8.0,   -- flat, per 4-digit 19xx/20xx token
  date               = 10.0,  -- flat, per parseable 6/8-digit date run
  dictionary_word    = 6.0,   -- flat, per embedded wordlist hit (len >= 4)
  leet               = 3.0,   -- flat, when substitutions add no real entropy
  short_per_char     = 2.5,   -- per missing char below length 8
  single_class       = 4.0,   -- flat, when only one character class is used
  variant_bonus      = 3.0,   -- extra cap room for leetified common passwords
}

M.MIN_GOOD_LENGTH = 8
M.MIN_WORD_LENGTH = 4          -- wordlist hits shorter than this are ignored

-- ---------------------------------------------------------------------------
-- Embedded common-password corpus (~500 entries, rank 1 = most common)
-- ---------------------------------------------------------------------------

local COMMON_RANK = {
  -- numeric sequences and phone-style patterns -------------------------------
  ["123456"] = 1, ["123456789"] = 2, ["12345678"] = 3, ["12345"] = 4,
  ["1234567"] = 5, ["1234567890"] = 6, ["1234"] = 7, ["123"] = 8,
  ["000000"] = 9, ["111111"] = 10, ["1111111"] = 11, ["11111111"] = 12,
  ["121212"] = 13, ["112233"] = 14, ["121314"] = 15, ["123123"] = 16,
  ["123321"] = 17, ["123654"] = 18, ["12341234"] = 19, ["1234qwer"] = 20,
  ["123654789"] = 21, ["123qwe"] = 22, ["147258369"] = 23,
  ["147852369"] = 24, ["159357"] = 25, ["159753"] = 26, ["102030"] = 27,
  ["100200"] = 28, ["13579"] = 29, ["246810"] = 30, ["2580"] = 31,
  ["314159"] = 32, ["520520"] = 33, ["54321"] = 34, ["555555"] = 35,
  ["666666"] = 36, ["777777"] = 37, ["7777777"] = 38, ["888888"] = 39,
  ["999999"] = 40, ["987654"] = 41, ["987654321"] = 42, ["696969"] = 43,
  ["112358"] = 44, ["111222"] = 45, ["010101"] = 46, ["101010"] = 47,
  ["456789"] = 48, ["567890"] = 49, ["789456"] = 50, ["789456123"] = 51,
  ["8675309"] = 52, ["5201314"] = 53, ["1234554321"] = 54, ["123abc"] = 55,
  ["1a2b3c"] = 56, ["a1b2c3"] = 57, ["0123456789"] = 58,
  -- keyboard walks ------------------------------------------------------------
  ["qwerty"] = 59, ["qwertyuiop"] = 60, ["qwerty123"] = 61,
  ["qwerty12"] = 62, ["qwe123"] = 63, ["qazwsx"] = 64,
  ["qazwsxedc"] = 65, ["1qaz2wsx"] = 66, ["1q2w3e4r"] = 67,
  ["1q2w3e"] = 68, ["2wsx3edc"] = 69, ["asdfgh"] = 70,
  ["asdfghjkl"] = 71, ["asdf1234"] = 72, ["asdf"] = 73,
  ["zxcvbnm"] = 74, ["zxcvbn"] = 75, ["zxcvbnm1"] = 76, ["poiuyt"] = 77,
  ["lkjhgf"] = 78, ["mnbvcx"] = 79, ["q1w2e3r4"] = 80, ["q1w2e3"] = 81,
  ["abcd1234"] = 82, ["abcd"] = 83, ["passw0rd"] = 84, ["p@ssw0rd"] = 85,
  ["passwd"] = 86,
  -- the evergreen words and phrases -------------------------------------------
  ["password"] = 87, ["password1"] = 88, ["password12"] = 89,
  ["password123"] = 90, ["password1234"] = 91, ["mypassword"] = 92,
  ["newpassword"] = 93, ["changeit"] = 94, ["changeme"] = 95,
  ["letmein"] = 96, ["letmein1"] = 97, ["welcome"] = 98,
  ["welcome1"] = 99, ["welcome123"] = 100, ["iloveyou"] = 101,
  ["iloveyou1"] = 102, ["trustno1"] = 103, ["whatever"] = 104,
  ["freedom"] = 105, ["secret"] = 106, ["sunshine"] = 107,
  ["shadow"] = 108, ["master"] = 109, ["monkey"] = 110,
  ["dragon"] = 111, ["princess"] = 112, ["angel"] = 113,
  ["babygirl"] = 114, ["babyboy"] = 115, ["sweetheart"] = 116,
  ["lovely"] = 117, ["loveme"] = 118, ["happiness"] = 119,
  ["guest"] = 120, ["user"] = 121, ["test"] = 122, ["test123"] = 123,
  ["sample"] = 124, ["demo"] = 125, ["temp"] = 126, ["default"] = 127,
  ["please"] = 128, ["money"] = 129, ["cash"] = 130, ["silver"] = 131,
  ["diamond"] = 132, ["platinum"] = 133, ["happy"] = 134, ["smile"] = 135,
  ["peace"] = 136, ["hope"] = 137, ["dream"] = 138, ["dreamer"] = 139,
  ["magic"] = 140, ["wonder"] = 141, ["destiny"] = 142, ["faith"] = 143,
  ["glory"] = 144, ["honor"] = 145, ["legend"] = 146,
  -- given names ---------------------------------------------------------------
  ["michael"] = 147, ["jennifer"] = 148, ["jordan"] = 149,
  ["taylor"] = 150, ["james"] = 151, ["robert"] = 152, ["john"] = 153,
  ["william"] = 154, ["david"] = 155, ["mary"] = 156, ["patricia"] = 157,
  ["linda"] = 158, ["jessica"] = 159, ["ashley"] = 160, ["amber"] = 161,
  ["daniel"] = 162, ["thomas"] = 163, ["sarah"] = 164, ["charles"] = 165,
  ["hannah"] = 166, ["anthony"] = 167, ["megan"] = 168, ["lauren"] = 169,
  ["emily"] = 170, ["samantha"] = 171, ["alexis"] = 172, ["olivia"] = 173,
  ["isabella"] = 174, ["sophia"] = 175, ["emma"] = 176, ["abigail"] = 177,
  ["madison"] = 178, ["elizabeth"] = 179, ["matthew"] = 180,
  ["andrew"] = 181, ["joshua"] = 182, ["joseph"] = 183, ["richard"] = 184,
  ["chris"] = 185, ["brian"] = 186, ["kevin"] = 187, ["jason"] = 188,
  ["justin"] = 189, ["brandon"] = 190, ["gary"] = 191, ["nicholas"] = 192,
  ["eric"] = 193, ["stephen"] = 194, ["larry"] = 195, ["scott"] = 196,
  ["ryan"] = 197, ["jacob"] = 198, ["tyler"] = 199, ["aaron"] = 200,
  ["adam"] = 201, ["henry"] = 202, ["harry"] = 203, ["jack"] = 204,
  ["charlie"] = 205, ["oliver"] = 206, ["george"] = 207, ["edward"] = 208,
  ["dennis"] = 209, ["jeremy"] = 210, ["samuel"] = 211, ["patrick"] = 212,
  ["alexander"] = 213, ["alex"] = 214, ["amanda"] = 215, ["nicole"] = 216,
  ["rachel"] = 217, ["tiffany"] = 218, ["danielle"] = 219,
  ["rebecca"] = 220, ["laura"] = 221, ["kimberly"] = 222,
  ["crystal"] = 223, ["brittany"] = 224, ["katherine"] = 225,
  ["stephanie"] = 226, ["michelle"] = 227, ["carol"] = 228,
  ["deborah"] = 229, ["diane"] = 230, ["susan"] = 231, ["karen"] = 232,
  ["nancy"] = 233, ["betty"] = 234, ["sandra"] = 235, ["sharon"] = 236,
  ["cynthia"] = 237, ["angela"] = 238, ["melissa"] = 239, ["brenda"] = 240,
  ["pamela"] = 241, ["jamie"] = 242, ["kelly"] = 243, ["tracy"] = 244,
  ["christine"] = 245, ["evelyn"] = 246, ["julie"] = 247, ["lori"] = 248,
  ["marie"] = 249, ["marilyn"] = 250, ["rose"] = 251, ["teresa"] = 252,
  ["virginia"] = 253, ["walter"] = 254, ["wayne"] = 255, ["gerald"] = 256,
  ["harold"] = 257, ["ronald"] = 258, ["jose"] = 259, ["maria"] = 260,
  ["carlos"] = 261, ["luis"] = 262, ["miguel"] = 263, ["jorge"] = 264,
  ["anna"] = 265, ["katie"] = 266, ["victoria"] = 267, ["grace"] = 268,
  ["bailey"] = 269,
  -- names + digit suffixes (ranked as one family) -------------------------------
  ["michael1"] = 270, ["jennifer1"] = 271, ["jessica1"] = 272,
  ["ashley1"] = 273, ["andrew1"] = 274, ["daniel1"] = 275,
  ["david1"] = 276, ["james1"] = 277, ["john1"] = 278, ["robert1"] = 279,
  ["william1"] = 280, ["joshua1"] = 281, ["matthew1"] = 282,
  ["thomas1"] = 283, ["kevin1"] = 284, ["jason1"] = 285, ["justin1"] = 286,
  ["brandon1"] = 287, ["ryan1"] = 288, ["jacob1"] = 289, ["tyler1"] = 290,
  ["charlie1"] = 291, ["jack1"] = 292, ["george1"] = 293,
  ["amanda1"] = 294, ["nicole1"] = 295, ["rachel1"] = 296,
  ["emily1"] = 297, ["hannah1"] = 298, ["katie1"] = 299,
  ["bailey1"] = 300, ["sarah1"] = 301,
  -- animals and nature ---------------------------------------------------------
  ["dolphin"] = 302, ["tiger"] = 303, ["lion"] = 304, ["bear"] = 305,
  ["bunny"] = 306, ["kitten"] = 307, ["puppy"] = 308,
  ["butterfly"] = 309, ["ladybug"] = 310, ["eagle"] = 311,
  ["falcon"] = 312, ["hawk"] = 313, ["wolf"] = 314, ["fox"] = 315,
  ["snake"] = 316, ["spider"] = 317, ["turtle"] = 318, ["penguin"] = 319,
  ["panda"] = 320, ["koala"] = 321, ["jaguar"] = 322, ["panther"] = 323,
  ["cheetah"] = 324, ["zebra"] = 325, ["giraffe"] = 326,
  ["elephant"] = 327, ["rhino"] = 328, ["hippo"] = 329, ["shark"] = 330,
  ["whale"] = 331, ["crab"] = 332, ["shrimp"] = 333, ["lobster"] = 334,
  ["salmon"] = 335, ["trout"] = 336, ["bass"] = 337, ["kitty"] = 338,
  ["doggy"] = 339, ["flower"] = 340, ["daisy"] = 341, ["lily"] = 342,
  ["sunflower"] = 343, ["tulip"] = 344, ["orchid"] = 345,
  ["rainbow"] = 346, ["cloud"] = 347, ["storm"] = 348, ["thunder"] = 349,
  ["lightning"] = 350, ["summer"] = 351, ["winter"] = 352, ["spring"] = 353,
  ["autumn"] = 354, ["ocean"] = 355, ["river"] = 356, ["mountain"] = 357,
  ["forest"] = 358, ["desert"] = 359, ["island"] = 360, ["sunset"] = 361,
  ["sunrise"] = 362, ["moonlight"] = 363, ["moon"] = 364, ["star"] = 365,
  ["sky"] = 366, ["earth"] = 367, ["fire"] = 368, ["water"] = 369,
  ["ice"] = 370, ["snow"] = 371, ["rain"] = 372, ["wind"] = 373,
  -- sports and teams -------------------------------------------------------------
  ["football"] = 374, ["baseball"] = 375, ["basketball"] = 376,
  ["soccer"] = 377, ["hockey"] = 378, ["tennis"] = 379, ["golfer"] = 380,
  ["boxing"] = 381, ["skating"] = 382, ["swimmer"] = 383,
  ["raiders"] = 384, ["lakers"] = 385, ["cowboys"] = 386,
  ["yankees"] = 387, ["redsox"] = 388, ["falcons"] = 389,
  ["ravens"] = 390, ["steelers"] = 391, ["packers"] = 392,
  ["broncos"] = 393, ["giants"] = 394, ["bears"] = 395, ["saints"] = 396,
  ["patriots"] = 397, ["celtics"] = 398, ["bulls"] = 399,
  ["blackhawks"] = 400, ["chelsea"] = 401, ["arsenal"] = 402,
  ["liverpool"] = 403, ["manchester"] = 404, ["barcelona"] = 405,
  ["realmadrid"] = 406, ["juventus"] = 407, ["cricket"] = 408,
  ["sports"] = 409, ["champion"] = 410, ["athlete"] = 411,
  ["varsity"] = 412, ["referee"] = 413, ["penalty"] = 414,
  ["striker"] = 415, ["keeper"] = 416, ["touchdown"] = 417,
  ["slamdunk"] = 418,
  -- films, series, games ---------------------------------------------------------
  ["superman"] = 419, ["batman"] = 420, ["spiderman"] = 421,
  ["ironman"] = 422, ["hulk"] = 423, ["thor"] = 424, ["loki"] = 425,
  ["avengers"] = 426, ["starwars"] = 427, ["yoda"] = 428,
  ["darthvader"] = 429, ["jedi"] = 430, ["harrypotter"] = 431,
  ["hogwarts"] = 432, ["hermione"] = 433, ["gryffindor"] = 434,
  ["dumbledore"] = 435, ["pokemon"] = 436, ["pikachu"] = 437,
  ["charizard"] = 438, ["mewtwo"] = 439, ["minecraft"] = 440,
  ["lego"] = 441, ["mario"] = 442, ["luigi"] = 443, ["yoshi"] = 444,
  ["zelda"] = 445, ["sonic"] = 446, ["goku"] = 447, ["vegeta"] = 448,
  ["naruto"] = 449, ["sasuke"] = 450, ["luffy"] = 451, ["conan"] = 452,
  ["tarzan"] = 453, ["merlin"] = 454, ["gandalf"] = 455, ["frodo"] = 456,
  ["aragorn"] = 457, ["legolas"] = 458,
  -- technology and brands ----------------------------------------------------------
  ["computer"] = 459, ["laptop"] = 460, ["internet"] = 461,
  ["network"] = 462, ["server"] = 463, ["admin"] = 464, ["admin1"] = 465,
  ["admin123"] = 466, ["administrator"] = 467, ["root"] = 468,
  ["toor"] = 469, ["linux"] = 470, ["ubuntu"] = 471, ["debian"] = 472,
  ["android"] = 473, ["apple"] = 474, ["iphone"] = 475, ["samsung"] = 476,
  ["google"] = 477, ["facebook"] = 478, ["twitter"] = 479,
  ["instagram"] = 480, ["netflix"] = 481, ["youtube"] = 482,
  ["amazon"] = 483, ["windows"] = 484, ["microsoft"] = 485, ["xbox"] = 486,
  ["playstation"] = 487, ["nintendo"] = 488, ["gamer"] = 489,
  ["gaming"] = 490, ["twitch"] = 491, ["discord"] = 492, ["spotify"] = 493,
  ["wifi"] = 494, ["firewall"] = 495, ["hacker"] = 496, ["matrix"] = 497,
  ["neo"] = 498, ["morpheus"] = 499, ["trinity"] = 500, ["oracle"] = 501,
  ["cisco"] = 502, ["kernel"] = 503, ["terminal"] = 504, ["bash"] = 505,
  ["python"] = 506,
  -- cars, food, drink --------------------------------------------------------------
  ["mustang"] = 507, ["corvette"] = 508, ["ferrari"] = 509,
  ["porsche"] = 510, ["lamborghini"] = 511, ["mercedes"] = 512,
  ["audi"] = 513, ["toyota"] = 514, ["honda"] = 515, ["nissan"] = 516,
  ["jeep"] = 517, ["truck"] = 518, ["biker"] = 519, ["chopper"] = 520,
  ["whiskey"] = 521, ["vodka"] = 522, ["beer"] = 523, ["wine"] = 524,
  ["coffee"] = 525, ["chocolate"] = 526, ["cookie"] = 527,
  ["pizza"] = 528, ["burger"] = 529, ["sugar"] = 530, ["spice"] = 531,
  -- heroes, myth, romance -----------------------------------------------------------
  ["danger"] = 532, ["killer"] = 533, ["gunner"] = 534, ["hunter"] = 535,
  ["ranger"] = 536, ["warrior"] = 537, ["ninja"] = 538, ["samurai"] = 539,
  ["pirate"] = 540, ["vampire"] = 541, ["zombie"] = 542, ["ghost"] = 543,
  ["demon"] = 544, ["phoenix"] = 545, ["titan"] = 546, ["omega"] = 547,
  ["alpha"] = 548, ["bravo"] = 549, ["delta"] = 550, ["juliet"] = 551,
  ["romeo"] = 552, ["casanova"] = 553, ["lover"] = 554, ["love"] = 555,
  ["harley"] = 556, ["rangers"] = 557, ["access"] = 558,
  -- music ----------------------------------------------------------------------------
  ["music"] = 559, ["guitar"] = 560, ["piano"] = 561, ["drums"] = 562,
  ["rocker"] = 563, ["metallica"] = 564, ["nirvana"] = 565,
  ["pinkfloyd"] = 566, ["beatles"] = 567, ["acdc"] = 568, ["eminem"] = 569,
  ["beyonce"] = 570, ["rihanna"] = 571, ["madonna"] = 572, ["elvis"] = 573,
  ["presley"] = 574, ["dylan"] = 575, ["mozart"] = 576,
  ["beethoven"] = 577, ["bach"] = 578, ["rockstar"] = 579,
  ["singer"] = 580, ["dancer"] = 581, ["melody"] = 582, ["harmony"] = 583,
  ["rhythm"] = 584, ["concert"] = 585,
  -- filler classics that round out the corpus ------------------------------------------
  ["lol"] = 586, ["haha"] = 587, ["hehe"] = 588, ["asdfgh1"] = 589,
  ["aaaaaa"] = 590, ["abc123456"] = 591, ["qweasdzxc"] = 592,
  ["iloveyou2"] = 593, ["liverpool1"] = 594, ["arsenal1"] = 595,
  ["chelsea1"] = 596, ["dragon1"] = 597, ["monkey1"] = 598,
  ["shadow1"] = 599, ["master1"] = 600, ["sunshine1"] = 601,
}

local COMMON_TOTAL = 0
for _ in pairs(COMMON_RANK) do
  COMMON_TOTAL = COMMON_TOTAL + 1
end

--- Number of embedded common passwords (exposed for specs and the CLI).
function M.common_count()
  return COMMON_TOTAL
end

--- Exact (case-insensitive) corpus lookup: rank or nil.
function M.common_rank(pw)
  if type(pw) ~= "string" then
    return nil
  end
  return COMMON_RANK[pw:lower()]
end

--- True when the password sits on the embedded corpus verbatim.
function M.is_common_password(pw)
  return M.common_rank(pw) ~= nil
end

-- ---------------------------------------------------------------------------
-- Leet-speak demangling
-- ---------------------------------------------------------------------------

-- Primary substitution table: every leet character maps to the letter it
-- visually replaces. "|" and "1" are ambiguous between i and l, so a second
-- candidate with the alternative reading is produced as well.
M.LEET_MAP = {
  ["4"] = "a", ["@"] = "a", ["8"] = "b", ["3"] = "e", ["6"] = "g",
  ["9"] = "g", ["1"] = "i", ["!"] = "i", ["0"] = "o", ["5"] = "s",
  ["$"] = "s", ["7"] = "t", ["+"] = "t", ["|"] = "i",
}

local LEET_ALT = { ["1"] = "l", ["|"] = "l" }

--- Demangle leet-speak: returns up to two lowercase candidate strings
-- (the i-reading and, when relevant, the l-reading of 1/|/!).
function M.demangle(pw)
  compat.check_str(pw, "pw")
  local primary, alt = {}, {}
  local has_alt = false
  local changed = false
  for i = 1, #pw do
    local ch = pw:sub(i, i)
    local low = ch:lower()
    local sub = M.LEET_MAP[low] or low
    primary[#primary + 1] = sub
    alt[#alt + 1] = sub
    if sub ~= low then
      changed = true
    end
    if LEET_ALT[low] then
      has_alt = true
      alt[#alt] = LEET_ALT[low]
    end
  end
  local out = { table.concat(primary) }
  if has_alt then
    local second = table.concat(alt)
    if second ~= out[1] then
      out[2] = second
    end
  end
  return out
end

--- True when the password uses at least one leet substitution.
function M.is_leet(pw)
  compat.check_str(pw, "pw")
  for i = 1, #pw do
    local low = pw:sub(i, i):lower()
    if M.LEET_MAP[low] then
      return true
    end
  end
  return false
end

-- ---------------------------------------------------------------------------
-- Corpus matching (exact, demangled, suffixed)
-- ---------------------------------------------------------------------------

--- Split "base12" into base + trailing digits (digits may be empty).
local function split_digit_suffix(s)
  local digits = s:match("(%d+)$")
  if not digits then
    return s, 0
  end
  return s:sub(1, #s - #digits), #digits
end

--- Look a lowercase candidate up directly, then after trimming a suffix of
-- digits or one trailing punctuation mark.
local function corpus_lookup(lowered)
  local rank = COMMON_RANK[lowered]
  if rank then
    return { kind = "exact", rank = rank, base = lowered, suffix_digits = 0 }
  end
  local base, ndigits = split_digit_suffix(lowered)
  if ndigits > 0 and ndigits <= 4 then
    rank = COMMON_RANK[base]
    if rank then
      return {
        kind = "suffix-digits", rank = rank, base = base,
        suffix_digits = ndigits,
      }
    end
  end
  local stripped = lowered:gsub("%p$", "")
  if #stripped < #lowered and #stripped > 0 then
    rank = COMMON_RANK[stripped]
    if rank then
      return {
        kind = "suffix-symbol", rank = rank, base = stripped,
        suffix_digits = 0,
      }
    end
  end
  return nil
end

--- Full corpus match: checks the password itself and every demangled
-- candidate. Returns nil or
-- { kind = "exact"|"suffix-digits"|"suffix-symbol"|"variant",
--   rank, base, suffix_digits, via_leet }.
function M.match_common(pw)
  compat.check_str(pw, "pw")
  local lowered = pw:lower()
  local hit = corpus_lookup(lowered)
  if hit then
    hit.via_leet = false
    return hit
  end
  local candidates = M.demangle(pw)
  for i = 1, #candidates do
    hit = corpus_lookup(candidates[i])
    if hit then
      hit.kind = "variant"
      hit.via_leet = true
      return hit
    end
  end
  return nil
end

-- ---------------------------------------------------------------------------
-- Pattern detectors (each returns an array of hits, possibly empty)
-- ---------------------------------------------------------------------------

--- Runs of 3+ ascending or descending characters ("abc", "987", "cba").
function M.detect_sequence(pw)
  compat.check_str(pw, "pw")
  local out = {}
  local n = #pw
  local i = 1
  while i < n do
    local dir = 0
    local c0 = pw:byte(i)
    local c1 = pw:byte(i + 1)
    if c1 == c0 + 1 then
      dir = 1
    elseif c1 == c0 - 1 then
      dir = -1
    end
    if dir ~= 0 then
      local j = i + 1
      while j < n do
        local a = pw:byte(j)
        local b = pw:byte(j + 1)
        if b == a + dir then
          j = j + 1
        else
          break
        end
      end
      local runlen = j - i + 1
      if runlen >= 3 then
        out[#out + 1] = {
          value = pw:sub(i, j), start = i, length = runlen,
          kind = dir == 1 and "ascending" or "descending",
        }
        i = j
      else
        i = i + 1
      end
    else
      i = i + 1
    end
  end
  return out
end

--- Repeated structure: 3+ identical characters ("aaa") and 4+ two-character
-- cycles ("ababab", "1212"). A trailing odd character of a cycle is not
-- flagged (documented limitation, keeps the detector deterministic).
function M.detect_repeats(pw)
  compat.check_str(pw, "pw")
  local out = {}
  local n = #pw
  local i = 1
  while i <= n do
    local j = i
    while j < n and pw:byte(j + 1) == pw:byte(i) do
      j = j + 1
    end
    local runlen = j - i + 1
    if runlen >= 3 then
      out[#out + 1] = {
        value = pw:sub(i, j), start = i, length = runlen, kind = "char",
      }
    end
    i = j + 1
  end
  i = 1
  while i + 3 <= n do
    local unit = pw:sub(i, i + 1)
    if unit:sub(1, 1) ~= unit:sub(2, 2) then
      local j = i + 2
      while j + 1 <= n and pw:sub(j, j + 1) == unit do
        j = j + 2
      end
      local runlen = j - i
      if runlen >= 4 then
        out[#out + 1] = {
          value = pw:sub(i, i + runlen - 1), start = i, length = runlen,
          kind = "cycle",
        }
        i = i + runlen
      else
        i = i + 1
      end
    else
      i = i + 1
    end
  end
  return out
end

-- Keyboard rows (and their reverses) precomputed at load time. Digits share
-- the top row, matching how people actually type walks like "1qaz".
local KEYBOARD_ROWS = {
  { name = "number row",   chars = "1234567890" },
  { name = "qwerty row",   chars = "qwertyuiop" },
  { name = "home row",     chars = "asdfghjkl" },
  { name = "bottom row",   chars = "zxcvbnm" },
}
local KEYBOARD_RUNS = {}
for r = 1, #KEYBOARD_ROWS do
  local chars = KEYBOARD_ROWS[r].chars
  KEYBOARD_RUNS[#KEYBOARD_RUNS + 1] = chars
  KEYBOARD_RUNS[#KEYBOARD_RUNS + 1] = chars:reverse()
end

--- Keyboard walks: 3+ consecutive keys on one physical row, forward or
-- reversed, case-insensitive ("Qwe", "1qaz" -> "qaz" hit, "asdf", ";lkj").
function M.detect_keyboard(pw)
  compat.check_str(pw, "pw")
  local lowered = pw:lower()
  local out = {}
  local n = #lowered
  local i = 1
  while i + 2 <= n do
    local found = nil
    local maxrun = math.min(10, n - i + 1)
    for len = maxrun, 3, -1 do
      local sub = lowered:sub(i, i + len - 1)
      for r = 1, #KEYBOARD_RUNS do
        if KEYBOARD_RUNS[r]:find(sub, 1, true) then
          found = {
            value = pw:sub(i, i + len - 1), start = i, length = len,
            row = KEYBOARD_ROWS[math.floor((r + 1) / 2)].name,
          }
          break
        end
      end
      if found then
        break
      end
    end
    if found then
      out[#out + 1] = found
      i = i + found.length
    else
      i = i + 1
    end
  end
  return out
end

--- 4-digit years 1900-2099 ("1984", "2023"). Each occurrence is a separate
-- finding: attackers enumerate year ranges far smaller than 10^4.
function M.detect_years(pw)
  compat.check_str(pw, "pw")
  local out = {}
  local n = #pw
  local i = 1
  while i + 3 <= n do
    local chunk = pw:sub(i, i + 3)
    if chunk:match("^%d%d%d%d$") then
      local year = tonumber(chunk)
      if year >= 1900 and year <= 2099 then
        out[#out + 1] = { value = chunk, start = i, year = year }
        i = i + 4
      else
        i = i + 1
      end
    else
      i = i + 1
    end
  end
  return out
end

local function is_month(m)
  return m >= 1 and m <= 12
end

local function is_day(d)
  return d >= 1 and d <= 31
end

--- Digit runs that parse as a calendar date in a common layout:
-- 8 digits as yyyymmdd or mmddyyyy, 6 digits as yymmdd/mmddyy/ddmmyy
-- (structurally identical for the detector). Day/month validation is
-- shallow (01-12 / 01-31); "0229" is accepted - documented simplification.
function M.detect_dates(pw)
  compat.check_str(pw, "pw")
  local out = {}
  local n = #pw
  local i = 1
  while i <= n do
    local j = i
    while j < n and pw:sub(j + 1, j + 1):match("%d") do
      j = j + 1
    end
    local runlen = j - i + 1
    if runlen == 6 or runlen == 8 then
      local run = pw:sub(i, j)
      local ok = false
      local shape = "unknown"
      if runlen == 8 then
        local y = tonumber(run:sub(1, 4))
        local mm = tonumber(run:sub(5, 6))
        local dd = tonumber(run:sub(7, 8))
        if y and y >= 1900 and y <= 2099 and is_month(mm) and is_day(dd) then
          ok = true
          shape = "yyyymmdd"
        else
          local m2 = tonumber(run:sub(1, 2))
          local d2 = tonumber(run:sub(3, 4))
          local y2 = tonumber(run:sub(5, 8))
          if is_month(m2) and is_day(d2) and y2 and y2 >= 1900 and y2 <= 2099 then
            ok = true
            shape = "mmddyyyy"
          end
        end
      else
        local a = tonumber(run:sub(1, 2))
        local b = tonumber(run:sub(3, 4))
        local c = tonumber(run:sub(5, 6))
        if is_month(b) and is_day(c) then
          ok = true
          shape = "yymmdd-family"
        elseif is_month(a) and is_day(b) then
          ok = true
          shape = "mmddyy-family"
        end
      end
      if ok then
        out[#out + 1] = { value = run, start = i, length = runlen, shape = shape }
      end
    end
    i = j + 1
  end
  return out
end

--- Embedded-wordlist hits of length >= 4 inside the password ("forge",
-- "dragon"...). Max 2 hits are reported; overlapping matches are skipped.
-- opts.min_word_length raises the threshold (never lowers it).
function M.detect_dictionary(pw, opts)
  compat.check_str(pw, "pw")
  opts = opts or {}
  local minlen = M.MIN_WORD_LENGTH
  if type(opts.min_word_length) == "number" and opts.min_word_length > minlen then
    minlen = math.floor(opts.min_word_length)
  end
  local lowered = pw:lower()
  local out = {}
  local words = wordlist.all()
  for w = 1, #words do
    local word = words[w]
    if #word >= minlen then
      local from = 1
      while true do
        local at = lowered:find(word, from, true)
        if not at then
          break
        end
        out[#out + 1] = { value = word, start = at, length = #word }
        if #out >= 2 then
          return out
        end
        from = at + 1
        lowered = lowered:sub(1, at - 1) .. string.rep("#", #word) ..
                  lowered:sub(at + #word)
      end
    end
  end
  return out
end

-- ---------------------------------------------------------------------------
-- The analyzer
-- ---------------------------------------------------------------------------

local function add_finding(findings, id, severity, title, detail, penalty)
  findings[#findings + 1] = {
    id = id,
    severity = severity,
    title = title,
    detail = detail,
    penalty = entropy.round2(penalty or 0),
  }
  return findings[#findings]
end

--- Analyze one password and return the full report table (see header).
-- opts.min_word_length overrides M.MIN_WORD_LENGTH for dictionary scans.
function M.analyze(pw, opts)
  if type(pw) ~= "string" then
    compat.fail("strength", "analyze expects a string, got '%s'", type(pw))
  end
  opts = opts or {}

  local length = #pw
  local counts = charsets.class_counts(pw)
  local pool = charsets.pool_size_for(pw)
  local base = entropy.effective_bits(pw)
  local findings = {}
  local deductions = 0

  local function penalize(amount)
    deductions = deductions + amount
    return amount
  end

  -- 1. structural minimums --------------------------------------------------
  if length == 0 then
    add_finding(findings, "empty", "critical",
      "Empty password", "No characters at all; nothing protects the account.", 0)
    deductions = 0
    base = 0
  elseif length < M.MIN_GOOD_LENGTH then
    local missing = M.MIN_GOOD_LENGTH - length
    add_finding(findings, "too-short", "critical",
      string.format("Too short (%d characters)", length),
      string.format("Lengths below %d fall to enumeration no matter the alphabet.",
        M.MIN_GOOD_LENGTH),
      penalize(missing * M.PENALTY.short_per_char))
  end

  local classes_used = 0
  for _, name in ipairs(charsets.order()) do
    if counts[name] > 0 then
      classes_used = classes_used + 1
    end
  end
  if length > 0 and classes_used == 1 then
    add_finding(findings, "single-class", "warning",
      "Single character class",
      "Only one of lower/upper/digits/symbols appears; keyboards-first attacks cover this.",
      penalize(M.PENALTY.single_class))
  end

  -- 2. corpus match (the heaviest possible verdict) --------------------------
  local common_hit = M.match_common(pw)
  if common_hit then
    local kind, detail
    if common_hit.kind == "exact" then
      kind = "common-password"
      detail = string.format("Rank #%d on the embedded common-password corpus.",
        common_hit.rank)
    elseif common_hit.kind == "variant" then
      kind = "common-variant"
      detail = string.format(
        "Leetified form of corpus entry '%s' (rank #%d); substitutions do not fool attackers.",
        common_hit.base, common_hit.rank)
    else
      kind = "common-suffix"
      detail = string.format(
        "Corpus entry '%s' (rank #%d) with a trailing suffix; suffixes of this shape are enumerated.",
        common_hit.base, common_hit.rank)
    end
    add_finding(findings, kind, "critical",
      "Found on common-password corpus", detail, 0)
  end

  -- 3. pattern detectors ------------------------------------------------------
  local seqs = M.detect_sequence(pw)
  for i = 1, #seqs do
    local hit = seqs[i]
    local extra = hit.length - 1
    add_finding(findings, "sequence", "warning",
      string.format("Sequence '%s'", hit.value),
      string.format("%d-character %s run; the rest of the keyspace around it collapses.",
        hit.length, hit.kind),
      penalize(extra * M.PENALTY.sequence_per_char))
  end

  local reps = M.detect_repeats(pw)
  for i = 1, #reps do
    local hit = reps[i]
    local extra = hit.length - (hit.kind == "char" and 1 or 2)
    add_finding(findings, "repeat", "warning",
      string.format("Repeat '%s'", hit.value),
      hit.kind == "char"
        and string.format("%d identical characters in a row.", hit.length)
        or string.format("%d-character two-key cycle.", hit.length),
      penalize(extra * M.PENALTY.repeat_per_char))
  end

  local walks = M.detect_keyboard(pw)
  for i = 1, #walks do
    local hit = walks[i]
    add_finding(findings, "keyboard-walk", "warning",
      string.format("Keyboard walk '%s'", hit.value),
      string.format("%d keys in a row on the %s.", hit.length, hit.row),
      penalize((hit.length - 2) * M.PENALTY.keyboard_per_char))
  end

  local years = M.detect_years(pw)
  for i = 1, #years do
    local hit = years[i]
    add_finding(findings, "year", "warning",
      string.format("Year '%s'", hit.value),
      "Four-digit years are among the first things attackers try as affixes.",
      penalize(M.PENALTY.year))
  end

  local dates = M.detect_dates(pw)
  for i = 1, #dates do
    local hit = dates[i]
    add_finding(findings, "date", "warning",
      string.format("Date '%s'", hit.value),
      string.format("Reads as a %s calendar date.", hit.shape),
      penalize(M.PENALTY.date))
  end

  local dict = M.detect_dictionary(pw, opts)
  for i = 1, #dict do
    local hit = dict[i]
    add_finding(findings, "dictionary-word", "warning",
      string.format("Dictionary word '%s'", hit.value),
      "Present in the embedded 1024-word list; wordlist attacks start here.",
      penalize(M.PENALTY.dictionary_word))
  end

  if M.is_leet(pw) and not common_hit then
    add_finding(findings, "leet-speak", "info",
      "Leet substitutions",
      "a->4, e->3 style swaps add essentially no entropy against modern crackers.",
      penalize(M.PENALTY.leet))
  end

  -- 4. combine -----------------------------------------------------------------
  local final_bits = base - deductions
  if common_hit then
    local cap = math.max(4, compat.log2(common_hit.rank + 1))
    cap = cap + common_hit.suffix_digits * compat.log2(10)
    if common_hit.kind == "variant" then
      cap = cap + M.PENALTY.variant_bonus
    end
    if final_bits > cap then
      final_bits = cap
    end
  end
  if final_bits < 0 then
    final_bits = 0
  end

  local verdict = entropy.scale_for(final_bits)
  return {
    password = pw,
    length = length,
    char_counts = counts,
    classes = charsets.describe_classes(pw),
    pool_size = pool,
    pool_bits = entropy.round2(entropy.bits_for_password(pw)),
    unique_bits = entropy.round2(entropy.unique_bits(pw)),
    shannon_bits = entropy.round2(entropy.shannon_bits(pw)),
    base_bits = entropy.round2(base),
    deductions = entropy.round2(deductions),
    entropy_bits = entropy.round2(final_bits),
    score = verdict.score,
    verdict = verdict.label,
    crack = entropy.crack_table(final_bits),
    findings = findings,
    is_common = common_hit ~= nil,
    common_rank = common_hit and common_hit.rank or nil,
  }
end

--- One-line human summary, e.g. "fair (42.35 bits, 2 findings)".
function M.summary_line(report)
  return string.format("%s (%.2f bits, %d finding%s)", report.verdict,
    report.entropy_bits, #report.findings,
    #report.findings == 1 and "" or "s")
end

return M
