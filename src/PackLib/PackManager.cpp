#include "PackManager.h"
#include <fstream>
#include <filesystem>

bool CPackManager::AddPack(const std::string& path)
{
	std::shared_ptr<CPack> pack = std::make_shared<CPack>();
	return pack->Open(path, m_entries);
}

bool CPackManager::GetFile(std::string_view path, TPackFile& result)
{
	thread_local std::string buf;
	NormalizePath(path, buf);

	if (m_load_from_pack) {
		auto it = m_entries.find(buf);
		if (it != m_entries.end()) {
			return it->second.first->GetFile(it->second.second, result);
		}
	}
	else {
		std::ifstream ifs(buf, std::ios::binary);
		if (ifs.is_open()) {
			ifs.seekg(0, std::ios::end);
			size_t size = ifs.tellg();
			ifs.seekg(0, std::ios::beg);
			result.resize(size);
			if (ifs.read((char*)result.data(), size)) {
				return true;
			}
		}
	}

	return false;
}

bool CPackManager::IsExist(std::string_view path) const
{
	thread_local std::string buf;
	NormalizePath(path, buf);

	if (m_load_from_pack) {
		auto it = m_entries.find(buf);
		return it != m_entries.end();
	}
	else {
		return std::filesystem::exists(buf);
	}
}

PACK_FORCEINLINE void CPackManager::NormalizePath(std::string_view in, std::string& out) const
{
	out.resize(in.size());
	for (std::size_t i = 0; i < out.size(); ++i) {
		if (in[i] == '\\')
			out[i] = '/';
		else
			out[i] = static_cast<char>(std::tolower(in[i]));
	}
}
