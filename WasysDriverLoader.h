//  WasysDriverLoader.h - deploy/undeploy the embedded libwasys.sys image.
#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <string>

namespace wasys
{
    // Service/file names.  A distinct file name is used on purpose so that a
    // legitimate OPSWAT installation of libwasys.sys is never overwritten.
    extern const wchar_t* kServiceName;      // L"WasysLab"
    extern const wchar_t* kDriverFileName;   // L"wasyslab.sys"
    // SHA-256 of the sample that was reversed.
    extern const wchar_t* kAnalysedSampleSha256;

    struct DriverState
    {
        bool         serviceExists  = false;
        bool         serviceRunning = false;
        bool         imageMatches   = false;
        std::wstring imagePath;          // as registered with the SCM
        DWORD        lastError      = 0;
    };

    bool         IsElevated();
    std::wstring DefaultDriverPath();        // C:\Windows\System32\drivers\wasyslab.sys

    // Reads IDR_WASYS_DRIVER, hashes it, and writes it to `dest` when the file
    // is missing or differs.  On success sha256Hex/bytes describe the blob.
    bool ExtractEmbeddedDriver(const std::wstring& dest,
                               std::wstring* sha256Hex, DWORD* bytes, std::wstring* err);

    // SHA-256 of an in-memory buffer, lowercase hex.
    std::wstring Sha256Hex(const void* data, SIZE_T len);

    // SCM primitives.
    bool QueryDriver(const std::wstring& service, DriverState* st);
    bool CreateDriverService(const std::wstring& service, const std::wstring& driverPath,
                             std::wstring* err);
    bool StartDriver(const std::wstring& service, std::wstring* err);
    bool StopDriver(const std::wstring& service, std::wstring* err);
    bool DeleteDriverService(const std::wstring& service, std::wstring* err);
    bool DeleteDriverFile(const std::wstring& path, std::wstring* err);

    // True when some instance of the device can be opened (driver already loaded).
    bool ProbeDevice();

    std::wstring Win32ErrText(DWORD code);
}
