-- lua-wordle — a Wordle-style word guessing game in pure Lua.
-- Run: lua wordle.lua

local WORDS = {
  "house", "plant", "smile", "brave", "cloud", "dream", "stone", "water",
  "light", "money", "world", "music", "night", "paper", "queen", "river",
  "space", "tiger", "voice", "watch", "youth", "zebra", "apple", "bread",
  "chair", "dance", "eagle", "flame", "grape", "heart", "jelly", "knife",
}

local COLORS = {
  reset = "\27[0m",
  green = "\27[32m",
  yellow = "\27[33m",
  gray = "\27[90m",
  bold = "\27[1m",
}

local function random_word()
  math.randomseed(os.time())
  return WORDS[math.random(#WORDS)]:upper()
end

local function feedback(guess, answer)
  -- returns a colored string: green=correct spot, yellow=wrong spot, gray=absent
  local result = {}
  local used = {}
  for i = 1, 5 do
    if guess[i] == answer[i] then
      result[i] = "green"
      used[answer[i]] = (used[answer[i]] or 0) + 1
    end
  end
  for i = 1, 5 do
    if not result[i] then
      local ch = guess[i]
      local count = 0
      for j = 1, 5 do
        if answer[j] == ch then count = count + 1 end
      end
      local already = used[ch] or 0
      if count > already then
        result[i] = "yellow"
        used[ch] = already + 1
      else
        result[i] = "gray"
      end
    end
  end

  local out = {}
  for i = 1, 5 do
    local color = COLORS[result[i]]
    table.insert(out, color .. " " .. guess[i] .. " " .. COLORS.reset)
  end
  return table.concat(out), result
end

local function is_valid(guess)
  return #guess == 5 and guess:match("^%a+$") ~= nil
end

local function main()
  local answer = random_word()
  local attempts_left = 6
  local won = false

  print(COLORS.bold .. "LUA WORDLE — doan tu 5 chu cai trong 6 luot" .. COLORS.reset)

  while attempts_left > 0 do
    io.write(string.format("\n[con %d luot] > ", attempts_left))
    io.stdout:flush()
    local raw = io.read("*l")
    if not raw then break end

    local guess = raw:upper():gsub("%s", "")
    if not is_valid(guess) then
      print(COLORS.gray .. "Tu phai co dung 5 chu cai." .. COLORS.reset)
    else
      local painted, marks = feedback({ guess:byte(1, -1) and string.byte and guess:sub(1, 1) or "",
                                        guess:sub(2, 2), guess:sub(3, 3),
                                        guess:sub(4, 4), guess:sub(5, 5) }, answer)
      print(painted)

      local all_green = true
      for _, m in ipairs(marks) do
        if m ~= "green" then all_green = false break end
      end

      if all_green then
        print(COLORS.green .. COLORS.bold .. "CHINH XAC! Ban da thang voi " ..
              (7 - attempts_left) .. " luot." .. COLORS.reset)
        won = true
        break
      end
      attempts_left = attempts_left - 1
    end
  end

  if not won then
    print(COLORS.yellow .. "\nHet luot! Tu dung la: " .. answer .. COLORS.reset)
  end
end

main()
