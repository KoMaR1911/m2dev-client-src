#pragma once
#include <string>
#include <mio/mmap.hpp>

#include "config.h"

class CPack : public std::enable_shared_from_this<CPack>
{
public:
	CPack() = default;
	~CPack() = default;

	bool Open(const std::string& path, TPackFileMap& entries);
	bool GetFile(const TPackFileEntry& entry, TPackFile& result);

private:
	TPackFileHeader m_header;
	mio::mmap_source m_file;

	CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption m_decryption;
};
