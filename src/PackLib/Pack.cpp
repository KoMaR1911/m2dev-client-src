#include "Pack.h"
#include <zstd.h>

bool CPack::Open(const std::string& path, TPackFileMap& entries)		  
{
	std::error_code ec;
	m_file.map(path, ec);

	if (ec) {
		return false;
	}
	size_t file_size = m_file.size();
	if (file_size < sizeof(TPackFileHeader)) {
		return false;
	}

	memcpy(&m_header, m_file.data(), sizeof(TPackFileHeader));
	alignas(32) uint8_t decrypted_key[32];
	memcpy(decrypted_key, PACK_KEY.data(), 32);
	compiletime_key_generation::decrypt_key<32>(decrypted_key, PACK_SEED_HASH);

	m_decryption.SetKeyWithIV(decrypted_key, 32, m_header.iv, CryptoPP::AES::BLOCKSIZE);  // it can be easyly hooked RTTI in binary shows it so extracting keys is still easy but not for begginers BEST IDEA IS NOT USE CRYPTOPP FOR THINGS LIKE IT BECAUSE OF EASY REVERSE ENGINEERING

	CryptoPP::SecureWipeBuffer(decrypted_key, 32);

	if (file_size < sizeof(TPackFileHeader) + m_header.entry_num * sizeof(TPackFileEntry)) {
		return false;
	}
	for (size_t i = 0; i < m_header.entry_num; i++) {
		TPackFileEntry entry;
		memcpy(&entry, m_file.data() + sizeof(TPackFileHeader) + i * sizeof(TPackFileEntry), sizeof(TPackFileEntry));
		m_decryption.ProcessData((CryptoPP::byte*)&entry, (CryptoPP::byte*)&entry, sizeof(TPackFileEntry));

		entries[entry.file_name] = std::make_pair(shared_from_this(), entry);

		if (file_size < m_header.data_begin + entry.offset + entry.compressed_size) {
			return false;
		}
	}
	return true;
}

bool CPack::GetFile(const TPackFileEntry& entry, TPackFile& result)	
{
	result.resize(entry.file_size);

	size_t offset = m_header.data_begin + entry.offset;
	switch (entry.encryption)
	{
		case 0: {
			size_t decompressed_size = ZSTD_decompress(result.data(), result.size(), m_file.data() + offset, entry.compressed_size);
			if (decompressed_size != entry.file_size) {
				return false;
			}
		} break;

		case 1: {
			std::vector<uint8_t> compressed_data(entry.compressed_size);
			memcpy(compressed_data.data(), m_file.data() + offset, entry.compressed_size);

			m_decryption.Resynchronize(entry.iv, sizeof(entry.iv));
			m_decryption.ProcessData(compressed_data.data(), compressed_data.data(), entry.compressed_size);

			size_t decompressed_size = ZSTD_decompress(result.data(), result.size(), compressed_data.data(), compressed_data.size());
			if (decompressed_size != entry.file_size) {
				return false;
			}
		} break;

		default: return false;
	}

	return true;
}
