#!/bin/bash

# Base32 字符表
BASE32_ALPHABET="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
tmp_file="/tmp/totp.tmp"

# 解码函数
base32_decode() {
    local input="$1"
    local bit_buffer=0
    local bits_in_buffer=0
    local decoded=""

    # 移除输入中的换行符和空格
    input=$(echo "$input" | tr -d '[:space:]')

    # 将输入转换为大写
    input=$(echo "$input" | tr '[:lower:]' '[:upper:]')

    # 使用传统的 for 循环语法
    local i=0
    while [ $i -lt ${#input} ]; do
        char="${input:$i:1}"
        # 查找字符在 Base32 字符表中的索引
        index=$(expr index "$BASE32_ALPHABET" "$char")
        if [ $index -eq 0 ]; then
            if [ "$char" = "=" ]; then
                break
            else
                echo "Invalid Base32 character: $char" >&2
                return 1
            fi
        fi
        # 修改为传统的减法操作
        index=$((index - 1))

        # 将索引值添加到位缓冲区
        bit_buffer=$((bit_buffer << 5 | index))
        bits_in_buffer=$((bits_in_buffer + 5))

        # 当位缓冲区中有足够的位时，提取字节
        while [ $bits_in_buffer -ge 8 ]; do
            byte=$((bit_buffer >> (bits_in_buffer - 8)))
            decoded="$decoded$(printf "\\$(printf '%03o' $byte)")"
            bit_buffer=$((bit_buffer & ((1 << (bits_in_buffer - 8)) - 1)))
            bits_in_buffer=$((bits_in_buffer - 8))
        done
        i=$((i + 1))
    done

    echo "$decoded"
}

# HMAC-SHA1 计算函数
hmac_sha1() {
    local key="$1"
    local data="$2"
    # 使用 openssl 计算 HMAC-SHA1
    # echo -n "$data" | base64 -d | openssl dgst -sha1 -hmac "$key" | cut -d' ' -f2
    echo -n "$data" | base64 -d | openssl dgst -sha1 -hmac "$key" -binary
}

# 将数字转换为大端序字节数组
number_to_big_endian_bytes() {
    local number="$1"
    local byte_array=""
    local hex_num=$(printf "%x" "$number")
    local len=${#hex_num}
    if [ $((len % 2)) -ne 0 ]; then
        hex_num="0$hex_num"
    fi
    local i=0
    while [ $i -lt $len ]; do
        byte=$(printf "\\x${hex_num:$i:2}")
        byte_array="$byte_array$byte"
        i=$((i + 2))
    done
    # echo "$byte_array"
    byte_len=${#byte_array}

    pad=$((8 - byte_len))
    $(printf '\0%.0s' $(seq 1 $pad) > "$tmp_file")
    $(printf '%b' $byte_array >> "$tmp_file")
    echo $(cat "$tmp_file" | base64)
}

# 主程序
if [ $# -lt 1 ]; then
    echo "Usage: $0 <base32_encoded_key> <number>"
    exit 1
fi
base32_encoded_key="$1"
number="$2"
if [ $# -ne 2 ]; then
    number=$(date +%s)
fi

number=$((number / 30))

# 进行 Base32 解码
decoded_key=$(base32_decode "$base32_encoded_key")

if [ $? -ne 0 ]; then
    exit 1
fi

echo -n "" > "$tmp_file"

# 将数字转换为大端序字节数组
byte_data=$(number_to_big_endian_bytes "$number")


# 计算 HMAC-SHA1
result=$(hmac_sha1 "$decoded_key" "$byte_data")

offset=$(printf "%d" "'${result:19:1}")
offset=$((offset & 0x0F))

bin_code="${result:$offset:4}"
num=0
i=0
while [ $i -lt 4 ]; do
	num=$((num << 8 | $(printf "%d" "'${bin_code:$i:1}")))
	# $(printf "%b\n" $num >> "$tmp_file")
	i=$((i + 1))
done
# $(echo $((num & 0x7FFFFFFF % 1000000)) >> "$tmp_file")
printf "%06d" $(((num & 0x7FFFFFFF) % 1000000))

# echo -n "" > "$tmp_file"
