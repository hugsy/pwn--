#include "Win32/Network.hpp"

#include <Urlmon.h>

#include "Log.hpp"

using namespace pwn;

Result<u64>
Net::HTTP::DownloadFile(std::string_view const& url, std::filesystem::path const& local_path)
{
    if ( std::filesystem::exists(local_path) && !std::filesystem::is_empty(local_path) )
    {
        return Err(Error::AlreadyExists);
    }

    auto const hRes = ::URLDownloadToFileA(nullptr, url.data(), local_path.string().c_str(), 0, 0);
    if ( hRes != S_OK )
    {
        err("URLDownloadFileToA() with failed: {x}", hRes);
        return Err(Error::ExternalApiCallFailed);
    }

    return Ok(std::filesystem::file_size(local_path));
}
