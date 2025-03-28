#pragma once

#include "Common.hpp"

namespace pwn::Net
{
class HTTP
{
public:
    ///
    ///@brief Download a file to disk
    ///
    ///@param url the URL of the file to download
    ///@param local_path the local path to use to store the file
    ///@return Result<u32> on success, the size of the downloaded file
    ///
    static Result<u64>
    DownloadFile(std::string_view const& url, std::filesystem::path const& local_path);
};
} // namespace pwn::Net
