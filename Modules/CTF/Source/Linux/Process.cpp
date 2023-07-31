#include "CTF/Linux/Process.hpp"

namespace pwn
{


Result<usize>
CTF::Process::send_internal(std::vector<u8> const& out)
{
    const usize count = out.size() & 0xffffffff;
    ssize res         = ::write(m_ChildPipeStdin, out.data(), count);
    if ( res < 0 )
    {
        ::perror("write()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(static_cast<usize>(res));
}


Result<std::vector<u8>>
CTF::Process::recv_internal(usize size)
{
    usize inbuf_sz = MIN(size, Tube::PIPE_DEFAULT_SIZE) & 0xffffffff;
    std::vector<u8> out(inbuf_sz);
    ssize res = ::read(m_ChildPipeStdout, out.data(), inbuf_sz);
    if ( res < 0 )
    {
        ::perror("read()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(std::move(out));
}


Result<usize>
CTF::Process::peek_internal()
{
    throw std::runtime_error("not implemented");
}


bool
CTF::Process::create_pipes()
{
    return false;
}


bool
CTF::Process::spawn_process()
{
    if ( !create_pipes() )
    {
        err(L"failed to create pipes\n");
        return false;
    }

    // TODO
    throw std::runtime_error("not implemented");
    return false;
}


} // namespace pwn
