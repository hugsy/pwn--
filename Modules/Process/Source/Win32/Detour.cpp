#include "Win32/Process.hpp"

EXTERN_C_START

///
///@brief
///
uptr HookCallbackLocation {0};

///
///@brief
///
///@return true
///@return false
///
bool
GoToTrampoline();

///
///@brief
///
///@return usize
///
usize
GoToTrampolineLength();

EXTERN_C_END

namespace pwn::Process
{

std::mutex HookLock;
std::mutex HookCallbackLock;


Result<bool>
Process::InsertCallback(std::function<void(PCONTEXT)> pFunction)
{
    std::lock_guard<std::mutex> ScopedLock(HookCallbackLock);

    //
    // Check if already inserted
    //
    if ( std::any_of(
             m_HookCallbacks.cbegin(),
             m_HookCallbacks.cend(),
             [pFunction](std::function<void(PCONTEXT)> const& fn)
             {
                 return std::addressof(fn) == std::addressof(pFunction);
             }) )
    {
        return Err(ErrorCode::AlreadyExists);
    }

    //
    // Insert the callback
    //
    m_HookCallbacks.push_back(pFunction);

    return Ok(true);
}


Result<bool>
Process::RemoveCallback(std::function<void(PCONTEXT)> pFunction)
{
    std::lock_guard<std::mutex> ScopedLock(HookCallbackLock);

    //
    // Check if function registered
    //
    auto const& it = std::find_if(
        m_HookCallbacks.cbegin(),
        m_HookCallbacks.cend(),
        [pFunction](std::function<void(PCONTEXT)> const& fn)
        {
            return std::addressof(fn) == std::addressof(pFunction);
        });

    if ( it == m_HookCallbacks.cend() )
    {
        return Err(ErrorCode::NotFound);
    }

    //
    // Remove the callback
    //
    m_HookCallbacks.erase(it);

    return Ok(true);
}


bool
Process::ExecuteCallbacks()
{
    //
    // RtlCaptureContext
    //
    CONTEXT ContextRecord {};
    ::RtlCaptureContext(&ContextRecord);

    //
    // Execute callbacks
    //
    {
        std::lock_guard<std::mutex> ScopedLock(HookCallbackLock);
        for ( auto const pFunction : m_HookCallbacks )
        {
            pFunction(&ContextRecord);
        }
    }

    //
    // Restore context and execute the original function
    //
    ::RtlRestoreContext(&ContextRecord, nullptr);

    // return ExecuteFunction();
    return true;
}


Result<bool>
Process::Hook(uptr Location)
{
    std::lock_guard<std::mutex> ScopedLock(HookLock);

    //
    // Check if trampoline has already been setup
    //
    if ( !HookCallbackLocation )
    {
        bool (Process::*pfn)() = &Process::ExecuteCallbacks;
        HookCallbackLocation   = (uptr)std::addressof(pfn);
    }

    //
    // Check the location is not already hooked
    //
    if ( std::any_of(
             m_Hooks.cbegin(),
             m_Hooks.cend(),
             [Location](auto const& h)
             {
                 return h.Location == Location;
             }) )
    {
        return Err(ErrorCode::AlreadyExists);
    }

    //
    // Lock and replace the bytes at the location
    //
    const usize len = GoToTrampolineLength();
    if ( !::VirtualLock((PVOID)Location, len) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    const std::vector<u8> Payload = Value(Memory.Read((uptr)std::addressof(GoToTrampoline), len));
    HookedLocation NewLoc {.Location = Location, .OriginalBytes = Value(Memory.Read(Location, len))};
    Memory.Write(Location, Payload);

    ::VirtualUnlock((PVOID)Location, len);

    //
    // Insert the new HookedLocation
    //
    m_Hooks.push_back(std::move(NewLoc));

    return Ok(true);
}


Result<bool>
Process::Unhook(uptr Location)
{
    std::lock_guard<std::mutex> ScopedLock(HookLock);

    //
    // Find a HookedLocation from the argument in m_Hooks
    //
    auto const it = std::find_if(
        m_Hooks.cbegin(),
        m_Hooks.cend(),
        [Location](auto const& h)
        {
            return h.Location == Location;
        });

    if ( it == m_Hooks.cend() )
    {
        return Err(ErrorCode::NotFound);
    }

    //
    // Lock and restore the original bytes
    //
    auto const& FoundHook = *it;

    if ( !::VirtualLock((PVOID)FoundHook.Location, FoundHook.OriginalBytes.size()) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    Memory.Write(Location, FoundHook.OriginalBytes);

    ::VirtualUnlock((PVOID)Location, FoundHook.OriginalBytes.size());

    //
    // Pop the vector entry
    //
    return Ok(true);
}
} // namespace pwn::Process
