#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>


#include <gcm.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <secblock.h>

#define PACK_FORCEINLINE __forceinline

namespace compiletime_key_generation
{
	PACK_FORCEINLINE constexpr uint64_t fnv1a_hash(const char* str) noexcept
	{
		uint64_t hash = 0xCBF29CE484222325ULL;
		for (;;)
		{
			const char c = *str++;
			if (!c)
				return hash;
			hash ^= (uint8_t)c;																												 
			hash *= 0x100000001B3ULL;
		}
	}

	PACK_FORCEINLINE constexpr uint64_t random_uint64(uint64_t seed)
	{
		seed ^= seed >> 21;
		seed *= 0xFF51AFD7ED558CCDULL;
		seed ^= seed >> 37;
		seed *= 0xC4CEB9FE1A85EC53ULL;
		seed ^= seed >> 11;
		return seed;
	}

	template<size_t KeySize>
	constexpr std::array<uint8_t, KeySize> generate_encrypted_key(const char* seed_string)
	{
		std::array<uint8_t, KeySize> key = {};
		uint64_t hash = fnv1a_hash(seed_string);

		for (size_t i = 0; i < KeySize; i++)
		{
			uint64_t byte_seed = random_uint64(hash + i * 0x9E3779B97F4A7C15ULL);
			key[i] = (uint8_t)(byte_seed & 0xFF);
		}

		for (size_t i = 0; i < KeySize; i++)
		{
			uint64_t op_seed = random_uint64(hash + i * 0x517CC1B727220A95ULL);
			key[i] ^= (uint8_t)(op_seed & 0xFF);
			key[i] += (uint8_t)((op_seed >> 8) & 0xFF);
			key[i] = (key[i] << 3) | (key[i] >> 5);
			key[i] *= (uint8_t)(((op_seed >> 16) & 0xFF) | 1);
			key[i] -= (uint8_t)((op_seed >> 24) & 0xFF);
			key[i] = ~key[i];
		}

		return key;
	}

	template<size_t KeySize>
	PACK_FORCEINLINE void decrypt_key(uint8_t* key, uint64_t hash)	   // ik it can be MUCH faster but its only PoC how to do it better and little harder to reverse engieenering
	{
		for (size_t i = 0; i < KeySize; i++)
		{
			uint64_t op_seed = random_uint64(hash + i * 0x517CC1B727220A95ULL);
			key[i] = ~key[i];
			key[i] += (uint8_t)((op_seed >> 24) & 0xFF);
			key[i] ^= (uint8_t)((((uint64_t)0x4E << 56) | ((uint64_t)0x65 << 48) | ((uint64_t)0x72 << 40) |
				((uint64_t)0x69 << 32) | ((uint64_t)0x74 << 24) | ((uint64_t)0x68 << 16)) >> (i % 8) * 8);
			uint8_t mul_val = (uint8_t)(((op_seed >> 16) & 0xFF) | 1);
			uint8_t mul_inv = mul_val;
			for (int j = 0; j < 6; j++)
				mul_inv = mul_inv * (2 - mul_val * mul_inv);
			key[i] *= mul_inv;
			key[i] = (key[i] >> 3) | (key[i] << 5);
			key[i] ^= (uint8_t)((((uint64_t)0x5A << 56) | ((uint64_t)0x6A << 48) | ((uint64_t)0x65 << 40) | ((uint64_t)0x62 << 32)) >> (i % 8) * 8);
			key[i] -= (uint8_t)((op_seed >> 8) & 0xFF);
			key[i] ^= (uint8_t)(op_seed & 0xFF);
		}
	}
}

constexpr const char PACK_SEED[] = "YOUR_KEY_TO_PACK123123123";	   // based on constexpr in compiletime to hash so string will not be visible :)


constexpr uint64_t PACK_SEED_HASH = compiletime_key_generation::fnv1a_hash(PACK_SEED);
constexpr auto PACK_KEY = compiletime_key_generation::generate_encrypted_key<32>(PACK_SEED);	 // PACK_KEY is encrypted at compile time so when someone will check binary it will be useless cuz we have decrypt_key 

#pragma pack(push, 1)
struct TPackFileHeader
{
	uint64_t	entry_num;
	uint64_t	data_begin;
	uint8_t     iv[CryptoPP::AES::BLOCKSIZE];
};
struct TPackFileEntry
{
	char		file_name[FILENAME_MAX + 1];
	uint64_t	offset;
	uint64_t	file_size;
	uint64_t	compressed_size;
	uint8_t		encryption;
	uint8_t     iv[CryptoPP::AES::BLOCKSIZE];
};
#pragma pack(pop)

class CPack;
using TPackFile = std::vector<uint8_t>;
using TPackFileMapEntry = std::pair<std::shared_ptr<CPack>, TPackFileEntry>;
using TPackFileMap = std::unordered_map<std::string, TPackFileMapEntry>;
