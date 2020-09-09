//
// Copyright (c) Johnny Shaw. All rights reserved.
// 
// File:     source/ProcessHerpaderping/utils.cpp
// Author:   Johnny Shaw
// Abstract: Utility functionality for herpaderping. 
//
#include "pch.hpp"
#include "utils.hpp"

namespace Utils
{
    static uint32_t g_LoggingMask{ 0xffffffff };
    constexpr static uint32_t MaxFileBuffer{ 0x8000 }; // 32kib
}

_Use_decl_annotations_
HRESULT Utils::MatchParameter(
    std::wstring_view Arg,
    std::optional<std::wstring_view> Short,
    std::optional<std::wstring_view> Long)
{
    if (Arg.length() < 2)
    {
        RETURN_LAST_ERROR_SET(ERROR_INVALID_PARAMETER);
    }

    if (Long.has_value() && (Arg[0] == L'-') && (Arg[1] == L'-'))
    {
        if (wcscmp(&Arg[2], Long->data()) == 0)
        {
            return S_OK;
        }
    }
    if (Short.has_value() && ((Arg[0] == L'-') || (Arg[0] == L'/')))
    {
        if (wcscmp(&Arg[1], Short->data()) == 0)
        {
            return S_OK;
        }
    }

    return E_FAIL;
}

_Use_decl_annotations_
HRESULT Utils::CheckForHelpOptions(
    int Argc,
    const wchar_t* Argv[])
{
    for (int i = 0; i < Argc; i++)
    {
        if (SUCCEEDED(MatchParameter(Argv[i], L"h", L"help")) || 
            SUCCEEDED(MatchParameter(Argv[i], L"?", std::nullopt)))
        {
            return S_OK;
        }
    }
    return E_NOT_SET;
}

_Use_decl_annotations_
HRESULT Utils::HandleCommandLineArgs(
    int Argc,
    const wchar_t* Argv[],
    std::optional<std::wstring_view> Header,
    IArgumentParser& Parser)
{
    if (SUCCEEDED(CheckForHelpOptions(Argc, Argv)) ||
        FAILED(Parser.ParseArguments(Argc, Argv)) ||
        FAILED(Parser.ValidateArguments()))
    {
        if (Header.has_value())
        {
            std::wcout << *Header << L'\n';
        }
        std::wcout << Parser.GetUsage();
        return E_FAIL;
    }

    return S_OK;
}

_Use_decl_annotations_
std::wstring Utils::FormatError(uint32_t Error)
{
    wil::unique_any<LPWSTR, decltype(&LocalFree), LocalFree> buffer;
    std::wstring message;
    auto length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                     FORMAT_MESSAGE_FROM_SYSTEM |
                                     FORMAT_MESSAGE_IGNORE_INSERTS,
                                 nullptr,
                                 Error,
                                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                 RCAST(LPWSTR)(&buffer),
                                 0,
                                 nullptr);
    if ((buffer != nullptr) && (length > 0))
    {
        message = std::wstring(buffer.get(), length);
    }
    else
    {
        length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                    FORMAT_MESSAGE_FROM_SYSTEM |
                                    FORMAT_MESSAGE_FROM_HMODULE |
                                    FORMAT_MESSAGE_IGNORE_INSERTS,
                                GetModuleHandleA("ntdll.dll"),
                                Error,
                                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                RCAST(LPWSTR)(&buffer),
                                0,
                                nullptr);
        if ((buffer != nullptr) && (length > 0))
        {
            //
            // NT status codes are formatted with inserts, only use the 
            // initial description if there is one, otherwise just use the 
            // string as is.
            //
            message = std::wstring(buffer.get(), length);
            if (message[0] == L'{')
            {
                auto pos = message.find(L'}', 1);
                if (pos != std::wstring::npos)
                {
                    message = std::wstring(message.begin() + 1,
                                           message.begin() + pos);
                }
            }
        }
    }

    if (message.empty())
    {
        message = L"Unknown Error";
    }

    std::wstringstream ss;
    ss << L"0x"
       << std::hex << std::setfill(L'0') << std::setw(8) << Error 
       << L" - "
       << std::move(message);

    auto res = ss.str();
    EraseAll(res, { L'\r', L'\n', L'\t' });

    return res;
}

_Use_decl_annotations_
void Utils::SetLoggingMask(uint32_t Level)
{
    g_LoggingMask = Level;
}

static const wchar_t* GetLogLevelPrefix(_In_ uint32_t Level)
{
    if (Level & Log::Error)
    {
        return L"[ERROR] ";
    }
    else if (Level & Log::Warning)
    {
        return L"[WARN]  ";
    }
    else if (Level & Log::Information)
    {
        return L"[INFO]  ";
    }
    else if (Level & Log::Debug)
    {
        return L"[DEBUG] ";
    }

    return L"[OK]    ";
}

static void LogInternal(
    _In_ bool AppendError,
    _In_ uint32_t Error,
    _In_ uint32_t Level,
    _Printf_format_string_ const wchar_t* Format,
    _In_ va_list Args)
{
    if ((Level & Utils::g_LoggingMask) == 0)
    {
        return;
    }

    std::wstring line;
    if (Utils::g_LoggingMask & Log::Context)
    {
        wil::str_printf_nothrow(line, 
                                L"[%lu:%lu]",
                                GetCurrentProcessId(),
                                GetCurrentThreadId());
    }

    line += GetLogLevelPrefix(Level);

    std::wstring fmt;
    HRESULT hr = wil::details::str_vprintf_nothrow(fmt, Format, Args);
    if (FAILED(hr))
    {
        fmt = L"Formatting Error " + Utils::FormatError(hr);
    }
    line += std::move(fmt);

    if (AppendError)
    {
        line += L", ";
        line += Utils::FormatError(Error);
    }

    if (Level & Log::Error)
    {
        std::wcerr << line << L'\n';
    }
    else
    {
        std::wcout << line << L'\n';
    }
}

_Use_decl_annotations_
void Utils::Log(
    uint32_t Level, 
    const wchar_t* Format, 
    ...)
{
    va_list args;
    va_start(args, Format);
    LogInternal(false, 0, Level, Format, args);
    va_end(args);
}

_Use_decl_annotations_
uint32_t Utils::Log(
    uint32_t Level, 
    uint32_t Error, 
    const wchar_t* Format, 
    ...)
{
    va_list args;
    va_start(args, Format);
    LogInternal(true, Error, Level, Format, args);
    va_end(args);
    return Error;
}

_Use_decl_annotations_
HRESULT Utils::FillBufferWithPattern(
    std::vector<uint8_t>& Buffer,
    std::span<const uint8_t> Pattern)
{
    if (Buffer.empty())
    {
        RETURN_LAST_ERROR_SET(ERROR_INVALID_PARAMETER);
    }

    auto bytesRemaining = Buffer.size();
    while (bytesRemaining > 0)
    {
        auto len = (Pattern.size() > bytesRemaining ? 
                    bytesRemaining 
                    : 
                    Pattern.size());

        std::memcpy(&Buffer[Buffer.size() - bytesRemaining],
                    Pattern.data(),
                    Pattern.size());

        bytesRemaining -= len;
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::FillBufferWithRandomBytes(
    std::vector<uint8_t>& Buffer)
{
    if (Buffer.empty())
    {
        RETURN_LAST_ERROR_SET(ERROR_INVALID_PARAMETER);
    }

    RETURN_IF_NTSTATUS_FAILED(
        BCryptGenRandom(nullptr,
                        Buffer.data(),
                        SCAST(ULONG)(Buffer.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG));

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::GetFileSize(
    handle_t FileHandle,
    uint64_t& FileSize)
{
    FileSize = 0;

    LARGE_INTEGER fileSize;
    RETURN_IF_WIN32_BOOL_FALSE(GetFileSizeEx(FileHandle, &fileSize));

    if (fileSize.QuadPart < 0)
    {
        RETURN_LAST_ERROR_SET(ERROR_FILE_INVALID);
    }

    FileSize = fileSize.QuadPart;
    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::SetFilePointer(
    handle_t FileHandle,
    int64_t DistanceToMove,
    uint32_t MoveMethod)
{
    LARGE_INTEGER distance;
    distance.QuadPart = DistanceToMove;

    RETURN_IF_WIN32_BOOL_FALSE_EXPECTED(SetFilePointerEx(FileHandle,
                                                         distance,
                                                         nullptr,
                                                         MoveMethod));
    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::CopyFileByHandle(
    handle_t SourceHandle, 
    handle_t TargetHandle,
    bool FlushFile)
{
    //
    // Get the file sizes.
    //
    uint64_t sourceSize;
    RETURN_IF_FAILED(GetFileSize(SourceHandle, sourceSize));

    uint64_t targetSize;
    RETURN_IF_FAILED(GetFileSize(TargetHandle, targetSize));

    //
    // Set the file pointers to the beginning of the files.
    //
    RETURN_IF_FAILED(SetFilePointer(SourceHandle, 0, FILE_BEGIN));
    RETURN_IF_FAILED(SetFilePointer(TargetHandle, 0, FILE_BEGIN));

    uint64_t bytesRemaining = sourceSize; 
    std::vector<uint8_t> buffer;
    if (bytesRemaining > MaxFileBuffer)
    {
        buffer.assign(MaxFileBuffer, 0);
    }
    else
    {
        buffer.assign(SCAST(size_t)(bytesRemaining), 0);
    }

    while (bytesRemaining > 0)
    {
        if (bytesRemaining < buffer.size())
        {
            buffer.assign(SCAST(size_t)(bytesRemaining), 0);
        }

        DWORD bytesRead = 0;
        RETURN_IF_WIN32_BOOL_FALSE(ReadFile(SourceHandle,
                                            buffer.data(),
                                            SCAST(DWORD)(buffer.size()),
                                            &bytesRead,
                                            nullptr));

        bytesRemaining -= bytesRead;

        DWORD bytesWitten = 0;
        RETURN_IF_WIN32_BOOL_FALSE(WriteFile(TargetHandle,
                                             buffer.data(),
                                             SCAST(DWORD)(buffer.size()),
                                             &bytesWitten,
                                             nullptr));
    }

    if (FlushFile)
    {
        RETURN_IF_WIN32_BOOL_FALSE(FlushFileBuffers(TargetHandle));
    }
    RETURN_IF_WIN32_BOOL_FALSE(SetEndOfFile(TargetHandle));

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::OverwriteFileContentsWithPattern(
    handle_t FileHandle,
    std::span<const uint8_t> Pattern,
    bool FlushFile)
{
    uint64_t targetSize;
    RETURN_IF_FAILED(GetFileSize(FileHandle, targetSize));
    RETURN_IF_FAILED(SetFilePointer(FileHandle, 0, FILE_BEGIN));

    uint64_t bytesRemaining = targetSize; 
    std::vector<uint8_t> buffer;
    if (bytesRemaining > MaxFileBuffer)
    {
        buffer.resize(MaxFileBuffer);
        RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
    }
    else
    {
        buffer.resize(SCAST(size_t)(bytesRemaining));
        RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
    }

    while (bytesRemaining > 0)
    {
        if (bytesRemaining < buffer.size())
        {
            buffer.resize(SCAST(size_t)(bytesRemaining));
            RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
        }

        DWORD bytesWritten = 0;
        RETURN_IF_WIN32_BOOL_FALSE(WriteFile(FileHandle,
                                             buffer.data(),
                                             SCAST(DWORD)(buffer.size()),
                                             &bytesWritten,
                                             nullptr));

        bytesRemaining -= bytesWritten;
    }

    if (FlushFile)
    {
        RETURN_IF_WIN32_BOOL_FALSE(FlushFileBuffers(FileHandle));
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::ExtendFileWithPattern(
    handle_t FileHandle,
    uint64_t NewFileSize,
    std::span<const uint8_t> Pattern,
    uint32_t& AppendedBytes,
    bool FlushFile)
{
    AppendedBytes = 0;

    uint64_t targetSize;
    RETURN_IF_FAILED(GetFileSize(FileHandle, targetSize));

    if (targetSize >= NewFileSize)
    {
        RETURN_LAST_ERROR_SET(ERROR_FILE_TOO_LARGE);
    }

    RETURN_IF_FAILED(SetFilePointer(FileHandle, 0, FILE_END));

    uint64_t bytesRemaining;
    bytesRemaining = (NewFileSize - targetSize);
    std::vector<uint8_t> buffer;
    if (bytesRemaining > MaxFileBuffer)
    {
        buffer.resize(MaxFileBuffer);
        RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
    }
    else
    {
        buffer.resize(SCAST(size_t)(bytesRemaining));
        RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
    }

    while (bytesRemaining > 0)
    {
        DWORD bytesWritten = 0;

        if (bytesRemaining < buffer.size())
        {
            buffer.resize(SCAST(size_t)(bytesRemaining));
            RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
        }

        RETURN_IF_WIN32_BOOL_FALSE(WriteFile(FileHandle,
                                             buffer.data(),
                                             SCAST(DWORD)(buffer.size()),
                                             &bytesWritten,
                                             nullptr));

        bytesRemaining -= bytesWritten;
        AppendedBytes += bytesWritten;
    }

    if (FlushFile)
    {
        RETURN_IF_WIN32_BOOL_FALSE(FlushFileBuffers(FileHandle));
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::OverwriteFileAfterWithPattern(
    handle_t FileHandle,
    uint64_t FileOffset,
    std::span<const uint8_t> Pattern,
    uint32_t& WrittenBytes,
    bool FlushFile)
{
    WrittenBytes = 0;

    uint64_t targetSize;
    RETURN_IF_FAILED(GetFileSize(FileHandle, targetSize));

    if (FileOffset >= targetSize)
    {
        RETURN_LAST_ERROR_SET(ERROR_INVALID_PARAMETER);
    }

    RETURN_IF_FAILED(SetFilePointer(FileHandle, FileOffset, FILE_BEGIN));

    uint64_t bytesRemaining;
    bytesRemaining = (targetSize - FileOffset);
    std::vector<uint8_t> buffer;
    if (bytesRemaining > MaxFileBuffer)
    {
        buffer.resize(MaxFileBuffer);
        RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
    }
    else
    {
        buffer.resize(SCAST(size_t)(bytesRemaining));
        RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
    }

    while (bytesRemaining > 0)
    {
        DWORD bytesWritten = 0;

        if (bytesRemaining < buffer.size())
        {
            buffer.resize(SCAST(size_t)(bytesRemaining));
            RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
        }

        RETURN_IF_WIN32_BOOL_FALSE(WriteFile(FileHandle,
                                             buffer.data(),
                                             SCAST(DWORD)(buffer.size()),
                                             &bytesWritten,
                                             nullptr));

        bytesRemaining -= bytesWritten;
        WrittenBytes += bytesWritten;
    }

    if (FlushFile)
    {
        RETURN_IF_WIN32_BOOL_FALSE(FlushFileBuffers(FileHandle));
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::ExtendFileSecurityDirectory(
    handle_t FileHandle,
    uint32_t ExtendedBy,
    bool FlushFile)
{
    uint64_t targetSize;
    RETURN_IF_FAILED(GetFileSize(FileHandle, targetSize));

    wil::unique_handle mapping;
    ULARGE_INTEGER mappingSize;
    mappingSize.QuadPart = targetSize;
    mapping.reset(CreateFileMappingW(FileHandle,
                                     nullptr,
                                     PAGE_READWRITE,
                                     mappingSize.HighPart,
                                     mappingSize.LowPart,
                                     nullptr));
    RETURN_LAST_ERROR_IF(!mapping.is_valid());

    wil::unique_mapview_ptr<void> view;
    view.reset(MapViewOfFile(mapping.get(),
                             FILE_MAP_READ | FILE_MAP_WRITE,
                             0,
                             0,
                             mappingSize.LowPart));
    RETURN_LAST_ERROR_IF(view == nullptr);

    auto dosHeader = RCAST(PIMAGE_DOS_HEADER)(view.get());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        //
        // This is not a PE file, we're done.
        //
        RETURN_LAST_ERROR_SET(ERROR_INVALID_IMAGE_HASH);
    }

    auto ntHeader = RCAST(PIMAGE_NT_HEADERS32)(Add2Ptr(view.get(), 
                                                       dosHeader->e_lfanew));
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        RETURN_LAST_ERROR_SET(ERROR_INVALID_IMAGE_HASH);
    }

    IMAGE_DATA_DIRECTORY* secDir;
    if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (ntHeader->OptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_SECURITY)
        {
            //
            // No security directory, we're done.
            //
            return S_OK;
        }
        secDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        auto ntHeader64 = RCAST(PIMAGE_NT_HEADERS64)(ntHeader);
        if (ntHeader64->OptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_SECURITY)
        {
            //
            // No security directory, we're done.
            //
            return S_OK;
        }
        secDir = &ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    else
    {
        RETURN_LAST_ERROR_SET(ERROR_INVALID_IMAGE_HASH);
    }

    if ((secDir->VirtualAddress) == 0 || (secDir->Size == 0))
    {
        //
        // No security directory, we're done.
        //
        return S_OK;
    }

    //
    // Extend the security directory size.
    //
    secDir->Size = (secDir->Size + ExtendedBy);

    RETURN_IF_WIN32_BOOL_FALSE(FlushViewOfFile(view.get(),
                                               mappingSize.LowPart));

    view.reset();
    mapping.reset();

    if (FlushFile)
    {
        RETURN_IF_WIN32_BOOL_FALSE(FlushFileBuffers(FileHandle));
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::GetImageEntryPointRva(
    handle_t FileHandle,
    uint32_t& EntryPointRva)
{
    EntryPointRva = 0;

    uint64_t fileSize;
    RETURN_IF_FAILED(GetFileSize(FileHandle, fileSize));

    ULARGE_INTEGER mappingSize;
    wil::unique_handle mapping;
    mappingSize.QuadPart = fileSize;
    mapping.reset(CreateFileMappingW(FileHandle,
                                     nullptr,
                                     PAGE_READONLY,
                                     mappingSize.HighPart,
                                     mappingSize.LowPart,
                                     nullptr));
    RETURN_LAST_ERROR_IF(!mapping.is_valid());

    wil::unique_mapview_ptr<void> view;
    view.reset(MapViewOfFile(mapping.get(),
                             FILE_MAP_READ,
                             0,
                             0,
                             mappingSize.LowPart));
    RETURN_LAST_ERROR_IF(view == nullptr);

    auto dosHeader = RCAST(PIMAGE_DOS_HEADER)(view.get());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        RETURN_LAST_ERROR_SET(ERROR_INVALID_IMAGE_HASH);
    }

    auto ntHeader = RCAST(PIMAGE_NT_HEADERS32)(Add2Ptr(view.get(),
                                                       dosHeader->e_lfanew));
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        RETURN_LAST_ERROR_SET(ERROR_INVALID_IMAGE_HASH);
    }

    if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        EntryPointRva = ntHeader->OptionalHeader.AddressOfEntryPoint;
    }
    else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        auto ntHeader64 = RCAST(PIMAGE_NT_HEADERS64)(ntHeader);
        EntryPointRva = ntHeader64->OptionalHeader.AddressOfEntryPoint;
    }
    else
    {
        RETURN_LAST_ERROR_SET(ERROR_INVALID_IMAGE_HASH);
    }

    return S_OK;
}

class OptionalUnicodeStringHelper
{
public:

    OptionalUnicodeStringHelper(
        _In_opt_ const std::optional<std::wstring>& String) :
        m_String(String)
    {
        if (m_String.has_value())
        {
            RtlInitUnicodeString(&m_Unicode, m_String->c_str());
        }
        else
        {
            RtlInitUnicodeString(&m_Unicode, L"");
        }
    }

    PUNICODE_STRING Get()
    {
        if (m_String.has_value())
        {
            return &m_Unicode;
        }
        return nullptr;
    }

    operator PUNICODE_STRING()
    {
        return Get();
    }

private:

    const std::optional<std::wstring>& m_String;
    UNICODE_STRING m_Unicode;

};

HRESULT RebaseProcessParameters(
    RTL_USER_PROCESS_PARAMETERS* Parameters,
    void* NewBase)
{
    //
    // The normalized process parameters are a contiguous block of memory, the 
    // pointers are all relative to the original base. Go through and re-base 
    // the addresses to the new base address.
    //
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->CurrentDirectory.DosPath.Buffer),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->DllPath.Buffer),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->ImagePathName.Buffer),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->CommandLine.Buffer),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->Environment),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->WindowTitle.Buffer),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->DesktopInfo.Buffer),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->ShellInfo.Buffer),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->RuntimeData.Buffer),
        Parameters,
        NewBase));
    for (size_t i = 0; i < RTL_MAX_DRIVE_LETTERS; i++)
    {
        RETURN_IF_FAILED(Utils::RebaseAddress(
            RCAST(void**)(&Parameters->CurrentDirectories[i].DosPath.Buffer),
            Parameters,
            NewBase));
    }
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->PackageDependencyData),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->RedirectionDllName.Buffer),
        Parameters,
        NewBase));
    RETURN_IF_FAILED(Utils::RebaseAddress(
        RCAST(void**)(&Parameters->HeapPartitionName.Buffer),
        Parameters,
        NewBase));
    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::WriteRemoteProcessParameters(
    handle_t ProcessHandle,
    const std::wstring ImageFileName,
    const std::optional<std::wstring>& DllPath,
    const std::optional<std::wstring>& CurrentDirectory,
    const std::optional<std::wstring>& CommandLine,
    void* EnvironmentBlock,
    const std::optional<std::wstring>& WindowTitle,
    const std::optional<std::wstring>& DesktopInfo,
    const std::optional<std::wstring>& ShellInfo,
    const std::optional<std::wstring>& RuntimeData)
{
    //
    // Get the basic info for the remote PEB address.
    //
    PROCESS_BASIC_INFORMATION pbi{};
    RETURN_IF_NTSTATUS_FAILED(NtQueryInformationProcess(
                                                      ProcessHandle,
                                                      ProcessBasicInformation,
                                                      &pbi,
                                                      sizeof(pbi),
                                                      nullptr));

    //
    // Generate the process parameters to write into the process.
    //
    UNICODE_STRING imageName;
    RtlInitUnicodeString(&imageName, ImageFileName.c_str());
    OptionalUnicodeStringHelper dllPath(DllPath);
    OptionalUnicodeStringHelper commandLine(CommandLine);
    OptionalUnicodeStringHelper currentDirectory(CurrentDirectory);
    OptionalUnicodeStringHelper windowTitle(WindowTitle);
    OptionalUnicodeStringHelper desktopInfo(DesktopInfo);
    OptionalUnicodeStringHelper shellInfo(ShellInfo);
    OptionalUnicodeStringHelper runtimeData(RuntimeData);
    wil::unique_user_process_parameters params;
    RETURN_IF_NTSTATUS_FAILED(RtlCreateProcessParametersEx(
                                            &params,
                                            &imageName,
                                            dllPath,
                                            currentDirectory,
                                            commandLine,
                                            EnvironmentBlock,
                                            windowTitle,
                                            desktopInfo,
                                            shellInfo,
                                            runtimeData,
                                            RTL_USER_PROC_PARAMS_NORMALIZED));

    //
    // Calculate the required length.
    //
    size_t len = params.get()->MaximumLength + params.get()->EnvironmentSize;

    //
    // Try to allocate in the remote process where the process parameters was 
    // allocated for us. This makes it easy to just copy in the current 
    // address.
    //
    void* remoteParams;
    auto remoteMemory = VirtualAllocEx(ProcessHandle,
                                       params.get(),
                                       len,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (remoteMemory != nullptr)
    {
        remoteParams = params.get();
    }
    else
    {
        Utils::Log(Log::Debug, 
                   L"Remote allocation failed, %p 0x%Ix",
                   params.get(),
                   len);
        //
        // Bummer, we'll need to allocate from anywhere and fix up the 
        // parameters...
        //
        remoteMemory = VirtualAllocEx(ProcessHandle,
                                      nullptr,
                                      len,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);

        RETURN_IF_NULL_ALLOC(remoteMemory);

        remoteParams = remoteMemory;

        Utils::Log(Log::Debug, 
                   L"Fixing up remote parameters, %p to %p",
                   params.get(),
                   remoteParams);

        RETURN_IF_FAILED(RebaseProcessParameters(params.get(),
                                                 remoteParams));

    }

    Utils::Log(Log::Debug, 
               L"Writing remote parameters, %p 0x%Ix",
               remoteParams,
               len);

    //
    // Write the parameters into the remote process.
    //
    RETURN_IF_WIN32_BOOL_FALSE(WriteProcessMemory(ProcessHandle,
                                                  remoteParams,
                                                  params.get(),
                                                  len,
                                                  nullptr));

    //
    // Write the parameter pointer to the remote process PEB.
    //
    RETURN_IF_WIN32_BOOL_FALSE(WriteProcessMemory(
                                 ProcessHandle,
                                 Add2Ptr(pbi.PebBaseAddress,
                                         FIELD_OFFSET(PEB, ProcessParameters)),
                                 &remoteParams,
                                 sizeof(remoteParams),
                                 nullptr));

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::RebaseAddress(
    void** Address,
    void* Base,
    void* NewBase)
{
    if (*Address == nullptr)
    {
        return S_OK;
    }
    ULONG_PTR addr = RCAST(ULONG_PTR)(*Address);
    ULONG_PTR origBase = RCAST(ULONG_PTR)(Base);
    ULONG_PTR newBase = RCAST(ULONG_PTR)(NewBase);
    ULONG_PTR rebased = 0;
    ULONG_PTR offset = 0;
    if (addr > origBase)
    {
        offset = (addr - origBase);
        if ((SCAST(ULONG_PTR)(-1) - newBase) < offset)
        {
            return E_FAIL;
        }
        rebased = newBase + offset;
    }
    else
    {
        offset = (addr - origBase);
        if (newBase < offset)
        {
            return E_FAIL;
        }
        rebased = newBase - offset;
    }

    *Address = RCAST(void*)(0ull + rebased);
    return S_OK;
}
