#include "Win32/Network.hpp"

#include <Urlmon.h>

using namespace pwn;

Result<u64>
Net::HTTP::DownloadFile(std::string_view const& url, std::filesystem::path const& local_path)
{
    if ( std::filesystem::exists(local_path) && !std::filesystem::is_empty(local_path) )
    {
        return Err(ErrorCode::AlreadyExists);
    }

    auto const hRes = ::URLDownloadToFileA(nullptr, url.data(), local_path.string().c_str(), 0, 0);
    if ( hRes != S_OK )
    {
        return Err(ErrorCode::ExternalApiCallFailed, hRes);
    }

    return Ok(std::filesystem::file_size(local_path));
}
