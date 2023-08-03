#pragma once

#include <sys/socket.h>
#include <sys/types.h>

// clang-format off
#include "Common.hpp"
#include "Handle.hpp"
#include "Tube.hpp"
#include "Utils.hpp"
// clang-format on

namespace pwn::CTF
{


///
/// @brief A Remote session
///
class Remote : public Net::Tube
{
public:
    Remote(std::wstring_view const& host, const u16 port);
    Remote(std::string_view const& host, const u16 port);

    ~Remote();

    ///
    ///@brief
    ///
    Result<bool>
    Connect();


    ///
    ///@brief
    ///
    Result<bool>
    Disconnect();


    ///
    ///@brief
    ///
    Result<bool>
    Reconnect();

protected:
    ///
    ///@brief
    ///
    Result<usize>
    send_internal(_In_ std::vector<u8> const& out);


    ///
    ///@brief
    ///
    Result<std::vector<u8>>
    recv_internal(_In_ usize size);


    ///
    ///@brief
    ///
    Result<usize>
    peek_internal();


private:
    ///
    ///@brief
    ///
    bool
    InitializeSocket();


private:
    std::wstring m_Host {};
    std::wstring m_Protocol {};
    u16 m_Port {};
    int m_Socket {};
};

} // namespace pwn::CTF
