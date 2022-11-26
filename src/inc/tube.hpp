#pragma once

#include "common.hpp"


///
/// @brief Generic interface that represent a tube. Tube definition (process, remote) are OS-specific
///
class Tube
{
public:
    ///
    ///@brief Default read size from the pipe
    ///
    static constexpr usize PIPE_DEFAULT_SIZE = 1024;

    ///
    ///@brief Default line separator
    ///
    static constexpr u8 LINE_SEPARATOR = '\n';

    ///
    ///@brief Default prompt
    ///
    static constexpr std::string_view INTERACTIVE_PROMPT = "(pwn)> ";


    ///
    ///@brief Move data given as argument to the send buffer, tries to send.
    ///
    ///@param str
    ///@return A Result object with the number of bytes sent
    PWNAPI Result<usize>
    send(std::vector<u8> const& str);

    ///
    ///@brief Move data given as argument to the send buffer, tries to send.
    ///
    ///@param str
    ///@return A Result object with the number of bytes sent
    ///
    PWNAPI Result<usize>
    send(std::string const& str);


    ///
    /// @brief Read bytes from the tube, moves the read bytes to the receive buffer.
    ///
    ///@param size The number of expected to be received (default: `Tube::PIPE_DEFAULT_SIZE`)
    ///@return Result<std::vector<u8>>
    ///
    Result<std::vector<u8>>
    recv(_In_ size_t size = Tube::PIPE_DEFAULT_SIZE);


    ///
    ///@brief Send the data (as byte vector) followed by a line separator
    ///
    ///@param data
    ///@return Result<usize> A Result object with the number of bytes sent
    ///
    Result<usize>
    sendline(_In_ std::vector<u8> const& data);

    ///
    ///@brief  Send the data (as str) followed by a line separator
    ///
    ///@param str
    ///@return Result<usize> A Result object with the number of bytes sent
    ///
    PWNAPI Result<usize>
    sendline(_In_ std::string const& str);


    ///
    ///@brief Read from tube until receiving the given pattern, and return that data.
    ///
    PWNAPI Result<std::vector<u8>>
    recvuntil(_In_ std::vector<u8> const& pattern);

    ///
    ///@brief
    ///
    ///@param pattern
    ///@return Result<std::vector<u8>>
    ///
    PWNAPI Result<std::vector<u8>>
    recvuntil(_In_ std::string const& pattern);


    ///
    ///@brief Read from tube until receiving a line separator and return it.
    ///
    PWNAPI Result<std::vector<u8>>
    recvline();


    ///
    ///@brief function combining in one call recvuntil() + send()
    ///
    ///@param pattern
    ///@param data
    ///@return
    ///
    PWNAPI Result<usize>
    sendafter(_In_ std::string const& pattern, _In_ std::string const& data);

    ///
    ///@brief
    ///
    ///@param pattern
    ///@param data
    ///@return Result<usize>
    ///
    PWNAPI Result<usize>
    sendafter(_In_ std::vector<u8> const& pattern, _In_ std::vector<u8> const& data);


    ///
    ///@brief Convenience function combining in one call recvuntil() + sendline()
    ///
    ///@param pattern
    ///@param data
    ///@return
    ///
    PWNAPI Result<usize>
    sendlineafter(_In_ std::string const& pattern, _In_ std::string const& data);

    ///
    ///@brief
    ///
    ///@param pattern
    ///@param data
    ///@return PWNAPI
    ///
    PWNAPI Result<usize>
    sendlineafter(_In_ std::vector<u8> const& pattern, _In_ std::vector<u8> const& data);


    ///
    /// @brief Peek into the tube to see if any data is available.
    ///
    PWNAPI Result<usize>
    peek();


    ///
    /// @brief Basic REPL.
    ///
    PWNAPI void
    interactive();


protected:
    Tube()  = default;
    ~Tube() = default;

    virtual Result<usize>
    send_internal(_In_ std::vector<u8> const& data) = 0;

    virtual Result<std::vector<u8>>
    recv_internal(_In_ size_t size) = 0;

    virtual Result<usize>
    peek_internal() = 0;

    std::vector<u8> m_receive_buffer;
    std::vector<u8> m_send_buffer;
};
