#pragma once

#include "common.hpp"


#define PWN_TUBE_PIPE_DEFAULT_SIZE 1024
#define PWN_LINESEP '\n'
#define PWN_INTERACTIVE_PROMPT ">>> "


///
/// Generic interface that represent a tube
/// Tube definition (process, remote) are OS-specific
///
class Tube
{
public:
    /// <summary>
    /// Move data given as argument to the send buffer, tries to send.
    /// This pure function should be defined for each new derived tube.
    /// </summary>
    PWNAPI auto send(_In_ std::vector<u8> const& str) -> size_t;
    PWNAPI auto send(_In_ std::string const& str) -> size_t;

    /// <summary>
    /// Read bytes from the tube, moves the read bytes to the receive buffer.
    /// This pure function should be defined for each new derived tube.
    /// </summary>
    PWNAPI auto recv(_In_ size_t size) -> std::vector<u8>;

    /// <summary>
    /// Send the data (as byte vector) followed by a line separator
    /// </summary>
    PWNAPI auto sendline(_In_ std::vector<u8> const& data) -> size_t;

    /// <summary>
    /// Send the data (as str) followed by a line separator
    /// </summary>
    /// <param name="str"></param>
    /// <returns></returns>
    PWNAPI auto sendline(_In_ std::string const& str) -> size_t;

    /// <summary>
    /// Read from tube until receiving the given pattern, and return that data.
    /// </summary>
    PWNAPI auto recvuntil(_In_ std::vector<u8> const& pattern) -> std::vector<u8>;
    PWNAPI auto recvuntil(_In_ std::string const& pattern) -> std::vector<u8>;

    /// <summary>
    /// Read from tube until receiving a line separator and return it.
    /// </summary>
    PWNAPI auto recvline() -> std::vector<u8>;

    /// <summary>
    /// Convenience function combining in one call recvuntil() + send()
    /// </summary>
    /// <param name="pattern"></param>
    /// <param name="data"></param>
    /// <returns></returns>
    PWNAPI auto sendafter(_In_ std::string const& pattern, _In_ std::string const& data) -> size_t;
    PWNAPI auto sendafter(_In_ std::vector<u8> const& pattern, _In_ std::vector<u8> const& data) -> size_t;

    /// <summary>
    /// Convenience function combining in one call recvuntil() + sendline()
    /// </summary>
    /// <param name="pattern"></param>
    /// <param name="data"></param>
    /// <returns></returns>
    PWNAPI auto sendlineafter(_In_ std::string const& pattern, _In_ std::string const& data) -> size_t;
    PWNAPI auto sendlineafter(_In_ std::vector<u8> const& pattern, _In_ std::vector<u8> const& data) -> size_t;

    /// <summary>
    /// Peek into the tube to see if any data is available.
    /// </summary>
    PWNAPI auto peek() -> size_t;

    /// <summary>
    /// Basic REPL.
    /// TODO: improve
    /// </summary>
    /// <returns></returns>
    PWNAPI void interactive();



protected:
    Tube()= default;
    ~Tube()= default;

    virtual auto __send_internal(_In_ std::vector<u8> const& data) -> size_t = 0;
    virtual auto __recv_internal(_In_ size_t size) -> std::vector<u8> = 0;
    virtual auto __peek_internal() -> size_t = 0;

    std::vector<u8> m_receive_buffer;
    std::vector<u8> m_send_buffer;
};




