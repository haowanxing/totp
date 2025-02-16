-- Base32 解码函数
local base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
function base32_decode(input)
    local output = {}
    local buffer = 0
    local bits_left = 0

    for i = 1, #input do
        local char = string.sub(input, i, i)
        local index = string.find(base32_chars, char, 1, true)
        if not index then
            if char ~= "=" then
                return nil
            end
            break
        end
        buffer = (buffer * 32) + (index - 1)
        bits_left = bits_left + 5
        if bits_left >= 8 then
            local byte = math.floor(buffer / (2 ^ (bits_left - 8)))
            table.insert(output, string.char(byte))
            buffer = buffer % (2 ^ (bits_left - 8))
            bits_left = bits_left - 8
        end
    end
    return table.concat(output)
end

-- 循环左移函数
function rol(num, shift)
    return ((num * (2 ^ shift)) % (2 ^ 32)) + math.floor(num / (2 ^ (32 - shift)))
end

-- 按位与操作
function band(a, b)
    local result = 0
    local bit = 1
    for i = 0, 31 do
        if (a % 2 == 1) and (b % 2 == 1) then
            result = result + bit
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

-- 按位或操作
function bor(a, b)
    local result = 0
    local bit = 1
    for i = 0, 31 do
        if (a % 2 == 1) or (b % 2 == 1) then
            result = result + bit
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

-- 按位异或操作
function bxor(a, b)
    local result = 0
    local bit = 1
    for i = 0, 31 do
        if (a % 2) ~= (b % 2) then
            result = result + bit
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

-- 按位取反操作
function bnot(a)
    return 0xFFFFFFFF - a
end

-- 左移操作
function lshift(a, shift)
    return (a * (2 ^ shift)) % (2 ^ 32)
end

-- 右移操作
function rshift(a, shift)
    return math.floor(a / (2 ^ shift))
end

-- SHA1 函数
function sha1(data)
    local h0 = 0x67452301
    local h1 = 0xefcdab89
    local h2 = 0x98badcfe
    local h3 = 0x10325476
    local h4 = 0xc3d2e1f0

    local message = data .. string.char(0x80)
    local len = #data * 8
    while (#message * 8) % 512 ~= 448 do
        message = message .. string.char(0x00)
    end
    message = message .. string.char(rshift(len, 56) % 256)
    message = message .. string.char(rshift(len, 48) % 256)
    message = message .. string.char(rshift(len, 40) % 256)
    message = message .. string.char(rshift(len, 32) % 256)
    message = message .. string.char(rshift(len, 24) % 256)
    message = message .. string.char(rshift(len, 16) % 256)
    message = message .. string.char(rshift(len, 8) % 256)
    message = message .. string.char(len % 256)

    for i = 1, #message, 64 do
        local block = string.sub(message, i, i + 63)
        local w = {}
        for j = 1, 16 do
            w[j] = lshift(string.byte(block, (j - 1) * 4 + 1), 24) +
                   lshift(string.byte(block, (j - 1) * 4 + 2), 16) +
                   lshift(string.byte(block, (j - 1) * 4 + 3), 8) +
                   string.byte(block, (j - 1) * 4 + 4)
        end
        for j = 17, 80 do
            w[j] = rol(bxor(w[j - 3], bxor(w[j - 8], bxor(w[j - 14], w[j - 16]))), 1)
        end

        local a = h0
        local b = h1
        local c = h2
        local d = h3
        local e = h4

        for j = 1, 80 do
            local f, k
            if j <= 20 then
                f = bor(band(b, c), band(bnot(b), d))
                k = 0x5A827999
            elseif j <= 40 then
                f = bxor(b, bxor(c, d))
                k = 0x6ED9EBA1
            elseif j <= 60 then
                f = bor(band(b, c), bor(band(b, d), band(c, d)))
                k = 0x8F1BBCDC
            else
                f = bxor(b, bxor(c, d))
                k = 0xCA62C1D6
            end
            local temp = (rol(a, 5) + f + e + k + w[j]) % (2 ^ 32)
            e = d
            d = c
            c = rol(b, 30)
            b = a
            a = temp
        end

        h0 = (h0 + a) % (2 ^ 32)
        h1 = (h1 + b) % (2 ^ 32)
        h2 = (h2 + c) % (2 ^ 32)
        h3 = (h3 + d) % (2 ^ 32)
        h4 = (h4 + e) % (2 ^ 32)
    end

    local result = string.char(rshift(h0, 24) % 256) ..
                   string.char(rshift(h0, 16) % 256) ..
                   string.char(rshift(h0, 8) % 256) ..
                   string.char(h0 % 256) ..
                   string.char(rshift(h1, 24) % 256) ..
                   string.char(rshift(h1, 16) % 256) ..
                   string.char(rshift(h1, 8) % 256) ..
                   string.char(h1 % 256) ..
                   string.char(rshift(h2, 24) % 256) ..
                   string.char(rshift(h2, 16) % 256) ..
                   string.char(rshift(h2, 8) % 256) ..
                   string.char(h2 % 256) ..
                   string.char(rshift(h3, 24) % 256) ..
                   string.char(rshift(h3, 16) % 256) ..
                   string.char(rshift(h3, 8) % 256) ..
                   string.char(h3 % 256) ..
                   string.char(rshift(h4, 24) % 256) ..
                   string.char(rshift(h4, 16) % 256) ..
                   string.char(rshift(h4, 8) % 256) ..
                   string.char(h4 % 256)

    return result
end

-- HMAC - SHA1 函数
function hmac_sha1(key, data)
    local block_size = 64
    if #key > block_size then
        key = sha1(key)
    end
    if #key < block_size then
        key = key .. string.rep(string.char(0x00), block_size - #key)
    end

    local o_key_pad = {}
    local i_key_pad = {}
    for i = 1, block_size do
        local key_byte = string.byte(key, i)
        o_key_pad[i] = string.char(bxor(key_byte, 0x5C))
        i_key_pad[i] = string.char(bxor(key_byte, 0x36))
    end
    o_key_pad = table.concat(o_key_pad)
    i_key_pad = table.concat(i_key_pad)

    return sha1(o_key_pad .. sha1(i_key_pad .. data))
end

-- 计算 TOTP 的函数
function generate_totp(base32_key, time_step, digits)
    -- 解码 base32 密钥
    local secret = base32_decode(base32_key)
    if not secret then
        error("Invalid base32 key")
    end

    -- 获取当前时间戳
    local current_time = os.time()
    -- 计算时间步长
    local counter = math.floor(current_time / time_step)

    -- 将计数器转换为 8 字节的大端字节序
    local counter_bytes = {}
    for i = 7, 0, -1 do
        counter_bytes[#counter_bytes + 1] = string.char(rshift(counter, i * 8) % 256)
    end
    local counter_data = table.concat(counter_bytes)

    -- 计算 HMAC-SHA1
    local hmac = hmac_sha1(secret, counter_data)

    -- 动态截断
    local offset = band(string.byte(hmac, #hmac), 0x0F)
    local binary = band(string.byte(hmac, offset + 1), 0x7F) * 0x1000000 +
                   band(string.byte(hmac, offset + 2), 0xFF) * 0x10000 +
                   band(string.byte(hmac, offset + 3), 0xFF) * 0x100 +
                   band(string.byte(hmac, offset + 4), 0xFF)

    -- 生成最终的 TOTP
    local totp = binary % (10 ^ digits)
    return string.format("%0" .. digits .. "d", totp)
end

if #arg < 1 then  
    print("Usage: lua totp.lua base32_secret_key")
    os.exit(1)
end
local base32_key = arg[1]
local time_step = 30  -- 时间步长为 30 秒
local digits = 6      -- 生成 6 位 TOTP

local totp = generate_totp(base32_key, time_step, digits)
print("TOTP: " .. totp)
