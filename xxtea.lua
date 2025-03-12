-- UTILS
local function toZeroBase(tbl)
	local newTbl = {}
	for i, v in ipairs(tbl) do
		newTbl[i - 1] = v
	end
	return newTbl
end

local function toOneBase(tbl)
    local newTbl = {}
    for i, v in pairs(tbl) do
        newTbl[i + 1] = v
    end
    return newTbl
end

local function overflow(n)
	local max_uint32 = 4294967295
	return ((n % (max_uint32 + 1)) + (max_uint32 + 1)) % (max_uint32 + 1)
end

-- XXTEA IMPLEMENTATION
local DELTA = 0x9E3779B9

local function xxtea_mx(sum, y, z, p, e, k)
	local p1 = bit32.bxor(bit32.rshift(z, 5), bit32.lshift(y, 2))
	local p2 = bit32.bxor(bit32.rshift(y, 3), bit32.lshift(z, 4))
	local p3 = bit32.bxor(sum, y)
	local p4 = bit32.bxor(k[bit32.bxor(bit32.band(p, 3), e)], z)

    return bit32.bxor(p1 + p2, p3 + p4)
end

-- V: array of numbers - what you want to encrypt
-- K: array of numbers - encryption key
function xxtea_encrypt(v, k)
	local v = toZeroBase(v)
	local k = toZeroBase(k)
	
	if #k < 2 then
		return v
	end

	local n = #v

	if n < 1 then
		return v
	end

	local z = v[n]
	local y = 0
	local sum = 0
	local e = 0
	local p = 0
	local q = 6 + math.floor(52 / (n + 1))

	local run = 0
	while true do
		if not (q > 0) then break end
		q -= 1
		run+=1

		sum = overflow(sum + DELTA)
		e = bit32.band(bit32.rshift(sum, 2), 3)
		for i = 0, n - 1 do
			p = i
			y = v[p + 1]
			v[p] = overflow(v[p] + xxtea_mx(sum, y, z, p, e, k))
			z = v[p]
		end
		p += 1
		y = v[0]
		v[n] = overflow(v[n] + xxtea_mx(sum, y, z, p, e, k))
		z = v[n]
	end

	return toOneBase(v)
end

-- V: arary of numbers - what you want to decrypt
-- K: array of numbers - encryption key
function xxtea_decrypt(v, k)
	local v = toZeroBase(v)
	local k = toZeroBase(k)

	if #k < 2 then
		return v
	end

	local n = #v
	local z = 0
	local y = v[0]
	local sum = 0
	local e = 0
	local p = 0
	local q = 6 + math.floor(52 / (n + 1))
	sum = overflow(math.floor(q * DELTA))
	while sum ~= 0 do
		e = bit32.band(bit32.rshift(sum, 2), 3)
		for i = n, 1, -1 do
            p = i
			z = v[p - 1]
			v[p] = overflow(v[p] - xxtea_mx(sum, y, z, p, e, k))
			y = v[p]
		end

		p-=1
		z = v[n]
		v[0] = overflow(v[0] - xxtea_mx(sum, y, z, p, e, k))
		y = v[0]
		sum = overflow(sum - DELTA)
	end
	return toOneBase(v)
end
