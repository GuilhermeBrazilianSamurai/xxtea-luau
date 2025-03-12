# xxtea-luau
Pure Luau implantation of xxtea encryption algorithm

## Usage
```lua
-- Helper
function string_to_bytes(str)
	local byte_table = {}
	for i = 1, #str do
		byte_table[i] = string.byte(str, i)
	end
	return byte_table
end

local text = "Hello World! 你好，中国！"
local key = string_to_bytes("1234567890")

local encrypt_data = xxtea_encrypt(string_to_bytes(text), key)
local decrypt_data = xxtea_decrypt(encrypt_data, key)

if text == string.char(unpack(decrypt_data)) then
	print("success!\n");
else
	print("fail!\n");
end
```
