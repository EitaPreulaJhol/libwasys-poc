//  WasysDriverLoader.cpp

#include "WasysDriverLoader.h"
#include "WasysDriverResource.h"

#include <bcrypt.h>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace wasys
{
    const wchar_t* kServiceName          = L"WasysLab";
    const wchar_t* kDriverFileName       = L"wasyslab.sys";
    const wchar_t* kAnalysedSampleSha256 =
        L"24a4dd32b633781c8c1193c9b445388ca7277799941a36ba9977b84382125e5c";

    //  Small helpers
    std::wstring Win32ErrText(DWORD code)
    {
        LPWSTR p = nullptr;
        DWORD n = ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                   FORMAT_MESSAGE_IGNORE_INSERTS,
                                   nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                   reinterpret_cast<LPWSTR>(&p), 0, nullptr);
        std::wstring s;
        if (n && p) s.assign(p, n);
        if (p) ::LocalFree(p);
        while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n' || s.back() == L' '))
            s.pop_back();
        if (s.empty())
        {
            wchar_t b[64];
            swprintf(b, _countof(b), L"Win32 error %lu", code);
            s = b;
        }
        return s;
    }

    bool IsElevated()
    {
        HANDLE tok = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tok))
            return false;
        TOKEN_ELEVATION el = {};
        DWORD len = 0;
        BOOL ok = ::GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &len);
        ::CloseHandle(tok);
        return ok && el.TokenIsElevated != 0;
    }

    std::wstring DefaultDriverPath()
    {
        wchar_t sys[MAX_PATH] = {};
        UINT n = ::GetSystemDirectoryW(sys, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return std::wstring(L"C:\\Windows\\System32\\drivers\\") + kDriverFileName;
        std::wstring p(sys, n);
        p += L"\\drivers\\";
        p += kDriverFileName;
        return p;
    }

    //  SHA-256 (bcrypt)
    std::wstring Sha256Hex(const void* data, SIZE_T len)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            return std::wstring(L"<sha256 unavailable>");

        BCRYPT_HASH_HANDLE hash = nullptr;
        std::wstring result;
        if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) >= 0)
        {
            BOOL good = FALSE;
            if (len == 0 || BCryptHashData(hash, const_cast<PUCHAR>(static_cast<const UCHAR*>(data)),
                                           static_cast<ULONG>(len), 0) >= 0)
            {
                UCHAR digest[32] = {};
                if (BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0)
                {
                    wchar_t hex[65];
                    for (int i = 0; i < 32; ++i)
                        swprintf(hex + i * 2, 3, L"%02x", digest[i]);
                    hex[64] = 0;
                    result = hex;
                    good = TRUE;
                }
            }
            BCryptDestroyHash(hash);
            (void)good;
        }
        BCryptCloseAlgorithmProvider(alg, 0);
        return result.empty() ? std::wstring(L"<sha256 failed>") : result;
    }

    //  Resource -> file
    bool ExtractEmbeddedDriver(const std::wstring& dest,
                               std::wstring* sha256Hex, DWORD* bytes, std::wstring* err)
    {
        HRSRC res = ::FindResourceW(::GetModuleHandleW(nullptr),
                                    MAKEINTRESOURCEW(IDR_WASYS_DRIVER), RT_RCDATA);
        if (!res)
        {
            DWORD e = ::GetLastError();
            *err = L"FindResource(IDR_WASYS_DRIVER) failed: " + Win32ErrText(e);
            return false;
        }

        DWORD size = ::SizeofResource(::GetModuleHandleW(nullptr), res);
        HGLOBAL glob = ::LoadResource(::GetModuleHandleW(nullptr), res);
        const void* blob = glob ? ::LockResource(glob) : nullptr;
        if (!size || !blob)
        {
            *err = L"the embedded driver resource is empty or unreadable";
            return false;
        }

        *bytes     = size;
        *sha256Hex = Sha256Hex(blob, size);

        // Already on disk with identical content?  Nothing to do (and this also
        // avoids a sharing violation when a driver instance still holds it).
        HANDLE probe = ::CreateFileW(dest.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (probe != INVALID_HANDLE_VALUE)
        {
            std::vector<BYTE> buf(size);
            DWORD got = 0;
            BOOL ok = ::ReadFile(probe, buf.data(), size, &got, nullptr);
            ::CloseHandle(probe);
            if (ok && got == size && Sha256Hex(buf.data(), got) == *sha256Hex)
                return true;      // identical file already present
        }
        else if (probe != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(probe);
        }

        HANDLE out = ::CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (out == INVALID_HANDLE_VALUE)
        {
            DWORD e = ::GetLastError();
            *err = L"cannot create \"" + dest + L"\": " + Win32ErrText(e) +
                   (e == ERROR_ACCESS_DENIED ? L" (run elevated)" : L"");
            return false;
        }

        DWORD written = 0;
        BOOL w = ::WriteFile(out, blob, size, &written, nullptr);
        ::FlushFileBuffers(out);
        ::CloseHandle(out);
        if (!w || written != size)
        {
            DWORD e = ::GetLastError();
            *err = L"WriteFile to \"" + dest + L"\" failed: " + Win32ErrText(e);
            return false;
        }
        return true;
    }

    //  SCM primitives
    bool QueryDriver(const std::wstring& service, DriverState* st)
    {
        *st = DriverState();
        st->lastError = 0;

        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            st->lastError = ::GetLastError();
            return false;
        }

        SC_HANDLE svc = ::OpenServiceW(scm, service.c_str(),
                                       SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        if (!svc)
        {
            st->lastError = ::GetLastError();
            ::CloseServiceHandle(scm);
            return st->lastError != ERROR_SERVICE_DOES_NOT_EXIST;
        }

        st->serviceExists = true;

        SERVICE_STATUS ss = {};
        if (::QueryServiceStatus(svc, &ss))
            st->serviceRunning = (ss.dwCurrentState == SERVICE_RUNNING);

        DWORD needed = 0;
        ::QueryServiceConfigW(svc, nullptr, 0, &needed);
        if (needed)
        {
            std::vector<BYTE> buf(needed);
            LPQUERY_SERVICE_CONFIGW cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buf.data());
            if (::QueryServiceConfigW(svc, cfg, needed, &needed) && cfg->lpBinaryPathName)
                st->imagePath = cfg->lpBinaryPathName;
        }

        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return true;
    }

    // Registers the driver image.  `driverPath` must be the absolute file path;
    // it is stored with the \??\ prefix that the kernel loader expects.
    bool CreateDriverService(const std::wstring& service, const std::wstring& driverPath,
                             std::wstring* err)
    {
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm)
        {
            DWORD e = ::GetLastError();
            *err = L"OpenSCManager(CREATE_SERVICE) failed: " + Win32ErrText(e) +
                   (e == ERROR_ACCESS_DENIED ? L" (run elevated)" : L"");
            return false;
        }

        std::wstring imagePath = L"\\??\\" + driverPath;

        SC_HANDLE svc = ::CreateServiceW(
            scm, service.c_str(), L"libwasys.sys lab harness (embedded driver)",
            DELETE | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            imagePath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);

        if (!svc)
        {
            DWORD e = ::GetLastError();
            ::CloseServiceHandle(scm);
            if (e == ERROR_SERVICE_EXISTS)
            {
                *err = L"service \"" + service + L"\" already exists";
                return false;
            }
            *err = L"CreateService failed: " + Win32ErrText(e);
            return false;
        }

        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return true;
    }

    bool StartDriver(const std::wstring& service, std::wstring* err)
    {
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            *err = L"OpenSCManager failed: " + Win32ErrText(::GetLastError());
            return false;
        }

        SC_HANDLE svc = ::OpenServiceW(scm, service.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
        if (!svc)
        {
            DWORD e = ::GetLastError();
            ::CloseServiceHandle(scm);
            *err = L"OpenService(\"" + service + L"\") failed: " + Win32ErrText(e);
            return false;
        }

        bool ok = ::StartServiceW(svc, 0, nullptr) != FALSE;
        if (!ok)
        {
            DWORD e = ::GetLastError();
            if (e == ERROR_SERVICE_ALREADY_RUNNING)
            {
                ::CloseServiceHandle(svc);
                ::CloseServiceHandle(scm);
                return true;
            }
            *err = L"StartService failed: " + Win32ErrText(e);
        }

        // Give the I/O manager a moment, then confirm.
        if (ok)
        {
            for (int i = 0; i < 20; ++i)
            {
                SERVICE_STATUS ss = {};
                if (::QueryServiceStatus(svc, &ss) && ss.dwCurrentState == SERVICE_RUNNING)
                    break;
                ::Sleep(50);
            }
        }

        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return ok;
    }

    bool StopDriver(const std::wstring& service, std::wstring* err)
    {
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            *err = L"OpenSCManager failed: " + Win32ErrText(::GetLastError());
            return false;
        }

        SC_HANDLE svc = ::OpenServiceW(scm, service.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!svc)
        {
            DWORD e = ::GetLastError();
            ::CloseServiceHandle(scm);
            if (e == ERROR_SERVICE_DOES_NOT_EXIST)
                return true;
            *err = L"OpenService(\"" + service + L"\") failed: " + Win32ErrText(e);
            return false;
        }

        SERVICE_STATUS ss = {};
        bool ok = ::ControlService(svc, SERVICE_CONTROL_STOP, &ss) != FALSE;
        if (!ok)
        {
            DWORD e = ::GetLastError();
            if (e != ERROR_SERVICE_NOT_ACTIVE)
                *err = L"ControlService(STOP) failed: " + Win32ErrText(e);
            ok = (e == ERROR_SERVICE_NOT_ACTIVE);
        }

        if (ok)
        {
            for (int i = 0; i < 40; ++i)     // up to 4 s
            {
                SERVICE_STATUS cur = {};
                if (!::QueryServiceStatus(svc, &cur))
                    break;
                if (cur.dwCurrentState == SERVICE_STOPPED)
                    break;
                ::Sleep(100);
            }
        }

        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return ok;
    }

    bool DeleteDriverService(const std::wstring& service, std::wstring* err)
    {
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            *err = L"OpenSCManager failed: " + Win32ErrText(::GetLastError());
            return false;
        }

        SC_HANDLE svc = ::OpenServiceW(scm, service.c_str(), DELETE);
        if (!svc)
        {
            DWORD e = ::GetLastError();
            ::CloseServiceHandle(scm);
            if (e == ERROR_SERVICE_DOES_NOT_EXIST)
                return true;
            *err = L"OpenService(DELETE) failed: " + Win32ErrText(e);
            return false;
        }

        bool ok = ::DeleteService(svc) != FALSE;
        if (!ok)
        {
            DWORD e = ::GetLastError();
            if (e != ERROR_SERVICE_MARKED_FOR_DELETE)
                *err = L"DeleteService failed: " + Win32ErrText(e);
            else
                ok = true;      // already pending removal
        }

        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return ok;
    }

    bool DeleteDriverFile(const std::wstring& path, std::wstring* err)
    {
        // The image can linger for a moment after the driver is unloaded.
        for (int i = 0; i < 25; ++i)     // up to 2.5 s
        {
            if (::DeleteFileW(path.c_str()))
                return true;

            DWORD e = ::GetLastError();
            if (e == ERROR_FILE_NOT_FOUND)
                return true;
            if (e != ERROR_SHARING_VIOLATION && e != ERROR_ACCESS_DENIED)
            {
                *err = L"DeleteFileW failed: " + Win32ErrText(e);
                return false;
            }
            ::Sleep(100);
        }

        // Last resort: remove it on the next boot, and say so.
        if (::MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT))
        {
            *err = L"file is still mapped - scheduled for deletion on the next reboot";
            return false;
        }

        *err = L"DeleteFileW failed: " + Win32ErrText(::GetLastError());
        return false;
    }

    bool ProbeDevice()
    {
        HANDLE h = ::CreateFileW(L"\\\\.\\WasysControl",
                                 GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return false;
        ::CloseHandle(h);
        return true;
    }
}
