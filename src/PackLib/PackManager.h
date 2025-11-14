#pragma once
#include <unordered_map>

#include "EterBase/Singleton.h"
#include "Pack.h"

class CPackManager : public CSingleton<CPackManager>
{
public:
	CPackManager() = default;
	virtual ~CPackManager() = default;

	bool AddPack(const std::string& path);
	bool GetFile(std::string_view path, TPackFile& result);
	bool IsExist(std::string_view path) const;

	void SetPackLoadMode() { m_load_from_pack = true; }
	void SetFileLoadMode() { m_load_from_pack = false; }

private:
	PACK_FORCEINLINE void NormalizePath(std::string_view in, std::string& out) const;

private:
	bool m_load_from_pack = true;
	TPackFileMap m_entries;
};
