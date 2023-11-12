#include "Win32/Process.hpp"


namespace pwn::Process
{

#pragma region Process::Memory

Memory::Memory(Process& _Process) : m_Process {_Process}
{
    auto res = m_Process.ReOpenProcessWith(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
    if ( Failed(res) )
    {
        throw std::runtime_error("Failed to get read/write access to the process");
    }
}

Result<std::vector<u8>>
Memory::Read(uptr const Address, usize Length)
{
    std::vector<u8> out(Length);
    SIZE_T NbByteRead {};
    if ( ::ReadProcessMemory(m_Process.Handle(), reinterpret_cast<LPVOID>(Address), out.data(), Length, &NbByteRead) ==
         false )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    out.resize(NbByteRead);
    return Ok(std::move(out));
}

Result<usize>
Memory::Memset(uptr const address, const usize size, const u8 val)
{
    auto data = std::vector<u8>(size);
    std::fill(data.begin(), data.end(), val);
    return Write(address, data);
}

Result<usize>
Memory::Write(uptr const Address, std::vector<u8> data)
{
    SIZE_T NbByteWritten {};
    if ( ::WriteProcessMemory(
             m_Process.Handle(),
             reinterpret_cast<LPVOID>(Address),
             data.data(),
             data.size(),
             &NbByteWritten) == false )
    {
        Log::perror("WriteProcessMemory");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(static_cast<usize>(NbByteWritten));
}

Result<uptr>
Memory::Allocate(const size_t Size, const wchar_t Permission[3], const uptr ForcedMappingAddress, bool wipe)
{
    u32 flProtect = 0;
    if ( ::wcscmp(Permission, L"r") == 0 )
    {
        flProtect |= PAGE_READONLY;
    }
    if ( ::wcscmp(Permission, L"rx") == 0 )
    {
        flProtect |= PAGE_EXECUTE_READ;
    }
    if ( ::wcscmp(Permission, L"rw") == 0 )
    {
        flProtect |= PAGE_READWRITE;
    }
    if ( ::wcscmp(Permission, L"rwx") == 0 )
    {
        flProtect |= PAGE_EXECUTE_READWRITE;
    }

    auto buffer = (uptr)::VirtualAllocEx(
        m_Process.Handle(),
        nullptr,
        Size,
        MEM_COMMIT | MEM_RESERVE,
        flProtect ? flProtect : PAGE_GUARD);
    if ( buffer == 0u )
    {
        return Err(ErrorCode::AllocationError);
    }

    if ( wipe )
    {
        Memset(buffer, Size, 0x00);
    }

    return Ok(buffer);
}

Result<bool>
Memory::Free(const uptr Address)
{
    if ( ::VirtualFreeEx(m_Process.Handle(), reinterpret_cast<LPVOID>(Address), 0, MEM_RELEASE) == 0 )
    {
        Log::perror(L"VirtualFreeEx");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(true);
}

Result<std::unique_ptr<u8[]>>
Memory::QueryInternal(
    const MEMORY_INFORMATION_CLASS MemoryInformationClass,
    const uptr BaseAddress,
    const usize InitialSize)
{
    ErrorCode ec = ErrorCode::UnknownError;
    usize Size   = InitialSize;

    auto Buffer = std::make_unique<u8[]>(Size);
    if ( !Buffer )
    {
        return Err(ErrorCode::AllocationError);
    }

    do
    {
        usize ReturnLength = 0;
        NTSTATUS Status    = ::NtQueryVirtualMemory(
            m_Process.Handle(),
            (PVOID)BaseAddress,
            MemoryInformationClass,
            Buffer.get(),
            Size,
            (PSIZE_T)&ReturnLength);
        if ( NT_SUCCESS(Status) )
        {
            break;
        }


        switch ( Status )
        {
        case STATUS_INFO_LENGTH_MISMATCH:
        case STATUS_BUFFER_TOO_SMALL:
        {
            Size   = ReturnLength;
            Buffer = std::make_unique<u8[]>(Size);
            continue;
        }
        default:
            break;
        }

        //
        // If doing an iteration, the last address will be invalid
        // resulting in having STATUS_INVALID_PARAMETER. We just exit.
        //
        ec = (Status == STATUS_INVALID_PARAMETER) ? ErrorCode::InvalidParameter : ErrorCode::PermissionDenied;

        Log::ntperror(L"NtQueryVirtualMemory()", Status);
        return Err(ec);

    } while ( true );

    return Ok(std::move(Buffer));
}


Result<std::vector<std::unique_ptr<MEMORY_BASIC_INFORMATION>>>
Memory::Regions()
{
    uptr CurrentAddress = 0;
    std::vector<std::unique_ptr<MEMORY_BASIC_INFORMATION>> MemoryRegions;

    while ( true )
    {
        //
        // Query the location
        //
        auto res = Query<MEMORY_BASIC_INFORMATION>(MEMORY_INFORMATION_CLASS::MemoryBasicInformation, CurrentAddress);
        if ( Failed(res) )
        {
            auto err = Error(res);
            if ( err == ErrorCode::InvalidParameter )
            {
                break;
            }

            return err;
        }

        //
        // Save the region information
        //
        auto CurrentMemoryRegion = Value(std::move(res));
        const usize RegionSize   = CurrentMemoryRegion->RegionSize;
        if ( CurrentMemoryRegion->AllocationBase != nullptr )
        {
            MemoryRegions.push_back(std::move(CurrentMemoryRegion));
        }

        //
        // Move to the next one
        //
        CurrentAddress += RegionSize;
    }

    return Ok(std::move(MemoryRegions));
}

Result<std::vector<uptr>>
Memory::Search(std::vector<u8> const& Pattern)
{
    if ( Pattern.empty() )
    {
        return Err(ErrorCode::InvalidParameter);
    }

    auto res = Regions();
    if ( Failed(res) )
    {
        return Error(res);
    }

    std::vector<uptr> Matches;
    auto const Regions = Value(std::move(res));

    for ( auto const& Region : Regions )
    {
        if ( Region->State != MEM_COMMIT )
        {
            continue;
        }

        if ( Region->Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE) == 0 )
        {
            continue;
        }

        if ( Region->Protect & (PAGE_GUARD | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY | PAGE_WRITECOMBINE) != 0 )
        {
            continue;
        }

        const uptr StartAddress = (uptr)Region->BaseAddress;
        const usize Size        = Region->RegionSize;

        if ( Size < Pattern.size() )
        {
            continue;
        }

        auto res = Read(StartAddress, Size);
        if ( Failed(res) )
        {
            continue;
        }

        auto const RemoteMemoryRegion = Value(std::move(res));
        usize CurrentIndex            = 0;
        const usize MaxSize           = RemoteMemoryRegion.size() - Pattern.size();

        while ( CurrentIndex < MaxSize )
        {
            usize Offset = 0;

            for ( auto const byte : Pattern )
            {
                if ( byte != RemoteMemoryRegion[CurrentIndex + Offset] )
                {
                    break;
                }

                Offset++;
            }

            if ( Offset == 0 )
            {
                CurrentIndex++;
                continue;
            }

            if ( Offset == Pattern.size() )
            {
                const uptr MatchingAddress = (uptr)(StartAddress + CurrentIndex);
                Matches.push_back(MatchingAddress);
            }

            CurrentIndex += Offset;
        }
    }
    return Ok(Matches);
}

#pragma endregion Process::Memory

} // namespace pwn::Process
