#include "Win32/Process.hpp"
#include "Win32/Thread.hpp"

namespace pwn::Process
{
#pragma region Process::ThreadGroup

/*
Result<std::vector<u32>>
ThreadGroup::List()
{
    if ( !m_Process )
    {
        return Err(ErrorCode::NotInitialized);
    }

    auto h = UniqueHandle {::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
    if ( !h )
    {
        Log::perror(L"CreateToolhelp32Snapshot()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<u32> tids;
    const u32 Pid    = m_Process->ProcessId();
    THREADENTRY32 te = {0};
    te.dwSize        = sizeof(te);
    if ( ::Thread32First(h.get(), &te) )
    {
        do
        {
            if ( !(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) )
                continue;
            if ( !te.th32ThreadID )
                continue;

            if ( te.th32OwnerProcessID != Pid )
                continue;

            tids.push_back(te.th32ThreadID);

            te.dwSize = sizeof(te);
        } while ( ::Thread32Next(h.get(), &te) );
    }

    return Ok(tids);
}

Thread
ThreadGroup::at(const u32 Tid)
{
    if ( !m_Process )
    {
        throw std::runtime_error("Thread initialization failed");
    }

    auto res = List();
    if ( Failed(res) )
    {
        throw std::runtime_error("Thread enumeration failed");
    }

    const auto tids = Value(res);
    if ( std::find(tids.cbegin(), tids.cend(), Tid) == std::end(tids) )
    {
        throw std::range_error("Invalid thread Id");
    }

    return Thread(Tid, m_Process);
}

Thread
ThreadGroup::operator[](u32 Tid)
{
    return at(Tid);
}
*/
#pragma endregion Process::ThreadGroup

} // namespace pwn::Process
