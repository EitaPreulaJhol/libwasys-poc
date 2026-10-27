//  FOR AUTHORISED SECURITY TESTING ONLY.
//
//  Build: build.bat (MSVC x64) or CMakeLists.txt.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <set>
#include <string>
#include <vector>

#include "WasysDriverLoader.h"

#pragma comment(lib, "comctl32.lib")

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' " \
                        "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

//  The single driver IOCTL this tool uses
#define WASYS_SYMLINK_NAME              L"\\\\.\\WasysControl"
#define IOCTL_WASYS_TERMINATE_PROCESS   0x22E00Cu   // METHOD_BUFFERED, device type 0x22
#define WASYS_TERM_INPUT_SIZE           4u          // the handler demands >= 4 bytes

//  Control identifiers/layout constants (96 dpi design units)
enum : int
{
    IDC_FILTER = 100,
    IDC_BTN_REFRESH,
    IDC_PROCVIEW,
    IDC_BTN_KILL,
    IDC_LOG
};

static const int kClientW = 560;
static const int kClientH = 436;

//  State
struct ProcEntry
{
    DWORD        pid;
    DWORD        ppid;
    DWORD        threads;
    std::wstring name;
};

static HWND   g_hwndMain    = nullptr;
static HWND   g_filter      = nullptr;
static HWND   g_procView    = nullptr;
static HWND   g_log         = nullptr;

static HANDLE g_device      = INVALID_HANDLE_VALUE;

static int    g_dpi         = 96;
static HFONT  g_fontUi      = nullptr;
static HFONT  g_fontMono    = nullptr;

static std::vector<ProcEntry> g_procs;

// Current sort order of the list view (column index + direction).
static int  g_sortCol = 1;        // 1 = "Image"
static bool g_sortAsc = true;

// Driver deployment bookkeeping -- what *this* session changed.
static std::wstring g_driverPath;
static std::wstring g_driverSha256;
static DWORD        g_driverBytes     = 0;
static bool         g_installedSvc    = false;   // we created the service
static bool         g_startedSvc      = false;   // we started the driver
static bool         g_loadedInSession = false;   // any of the above happened here

static int S(int v) { return MulDiv(v, g_dpi, 96); }

//  Small helpers
static void CopyW(WCHAR* dst, size_t cch, const WCHAR* src)
{
    if (!cch) return;
    size_t i = 0;
    for (; i + 1 < cch && src && src[i]; ++i) dst[i] = src[i];
    dst[i] = L'\0';
}

static std::wstring GetText(HWND h)
{
    int n = ::GetWindowTextLengthW(h);
    if (n <= 0) return std::wstring();
    std::vector<WCHAR> buf(static_cast<size_t>(n) + 1, 0);
    ::GetWindowTextW(h, buf.data(), n + 1);
    return std::wstring(buf.data());
}

static void Log(const WCHAR* fmt, ...)
{
    if (!g_log) return;

    SYSTEMTIME st;
    ::GetLocalTime(&st);

    WCHAR stamp[32];
    swprintf(stamp, _countof(stamp), L"%02u:%02u:%02u.%03u  ",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    WCHAR body[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(body, _countof(body), fmt, ap);
    va_end(ap);
    body[_countof(body) - 1] = L'\0';

    std::wstring line = std::wstring(stamp) + body + L"\r\n";
    int len = ::GetWindowTextLengthW(g_log);
    ::SendMessageW(g_log, EM_SETSEL, static_cast<WPARAM>(len), static_cast<LPARAM>(len));
    ::SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
    ::SendMessageW(g_log, EM_SCROLLCARET, 0, 0);
}

static int SelectedItemCount();

static void UpdateUiState()
{
    const BOOL attached     = (g_device != INVALID_HANDLE_VALUE);
    const BOOL hasSelection = (SelectedItemCount() > 0);

    HWND h;
    if ((h = ::GetDlgItem(g_hwndMain, IDC_BTN_KILL)))
        ::EnableWindow(h, attached && hasSelection);
}

//  Attach / detach the device object
static bool AttachDevice()
{
    if (g_device != INVALID_HANDLE_VALUE) return true;

    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 30; ++attempt)     // driver may still be binding
    {
        h = ::CreateFileW(WASYS_SYMLINK_NAME,
                          GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        ::Sleep(100);
    }
    if (h == INVALID_HANDLE_VALUE)
    {
        DWORD e = ::GetLastError();
        Log(L"  attach failed: CreateFileW(%s) -> 0x%08lX (%s)",
            WASYS_SYMLINK_NAME, e, wasys::Win32ErrText(e).c_str());
        UpdateUiState();
        return false;
    }

    g_device = h;
    UpdateUiState();
    return true;
}

static void DetachDevice()
{
    if (g_device == INVALID_HANDLE_VALUE) return;
    ::CloseHandle(g_device);
    g_device = INVALID_HANDLE_VALUE;
    UpdateUiState();
}


//  Driver deployment: extract from the embedded resource, register, start, then attach.
static bool DeployDriverAndAttach()
{
    if (wasys::ProbeDevice())
    {
        if (!AttachDevice()) return false;
        Log(L"attached (driver was already running)");
        return true;
    }

    if (!wasys::IsElevated())
    {
        // The manifest requests requireAdministrator, so this is only reached if
        // the manifest was stripped.  Do it by hand in that case:
        Log(L"Not elevated: cannot extract/register/start a kernel driver.");
        Log(L"    sc create WasysLab type= kernel binPath= \\??\\%s", g_driverPath.c_str());
        Log(L"    sc start WasysLab");
        UpdateUiState();
        return false;
    }

    // extract
    std::wstring err;
    if (!wasys::ExtractEmbeddedDriver(g_driverPath, &g_driverSha256, &g_driverBytes, &err))
    {
        Log(L"driver deploy failed: %s", err.c_str());
        UpdateUiState();
        return false;
    }

    if (_wcsicmp(g_driverSha256.c_str(), wasys::kAnalysedSampleSha256) != 0)
        Log(L"WARNING: embedded image is not the analysed sample (sha256 %s)",
            g_driverSha256.c_str());

    // service
    wasys::DriverState st;
    wasys::QueryDriver(wasys::kServiceName, &st);

    if (st.serviceExists)
    {
        const std::wstring expected = L"\\??\\" + g_driverPath;
        if (!st.imagePath.empty() && _wcsicmp(st.imagePath.c_str(), expected.c_str()) != 0)
        {
            Log(L"service \"%s\" already exists but points at \"%s\"",
                wasys::kServiceName, st.imagePath.c_str());
            Log(L"refusing to hijack it - remove it first:  sc delete %s", wasys::kServiceName);
            UpdateUiState();
            return false;
        }
    }
    else
    {
        if (!wasys::CreateDriverService(wasys::kServiceName, g_driverPath, &err))
        {
            Log(L"driver deploy failed: %s", err.c_str());
            UpdateUiState();
            return false;
        }
        g_installedSvc    = true;
        g_loadedInSession = true;
    }

    // start
    if (!st.serviceRunning)
    {
        if (!wasys::StartDriver(wasys::kServiceName, &err))
        {
            Log(L"driver start failed: %s", err.c_str());
            if (g_installedSvc)
            {
                std::wstring e2;
                wasys::DeleteDriverService(wasys::kServiceName, &e2);
                wasys::DeleteDriverFile(g_driverPath, &e2);
                g_installedSvc    = false;
                g_loadedInSession = false;
            }
            UpdateUiState();
            return false;
        }
        g_startedSvc      = true;
        g_loadedInSession = true;
    }

    // attach
    if (!AttachDevice()) return false;
    Log(L"attached (driver deployed by this session)");
    return true;
}

//  Driver "undeployment": detach, stop, delete service, delete image.
static void UnloadDriver()
{
    DetachDevice();      // no live IRP source before the driver unloads

    if (!g_startedSvc && !g_installedSvc)
    {
        // nothing was deployed by this session - nothing to undo
        return;
    }
    if (!wasys::IsElevated())
    {
        Log(L"cannot stop/delete the kernel service without elevation");
        return;
    }

    std::wstring err;
    bool ok = true;

    if (g_startedSvc)
    {
        if (!wasys::StopDriver(wasys::kServiceName, &err))
        {
            Log(L"driver stop failed: %s", err.c_str());
            ok = false;
        }
        g_startedSvc = false;
    }

    if (g_installedSvc)
    {
        if (!wasys::DeleteDriverService(wasys::kServiceName, &err))
        {
            Log(L"service delete failed: %s", err.c_str());
            ok = false;
        }
        if (!wasys::DeleteDriverFile(g_driverPath, &err))
        {
            Log(L"image delete failed: %s", err.c_str());
            ok = false;
        }
        g_installedSvc = false;
    }

    if (ok)
        Log(L"detached, driver unloaded, service and image removed");

    g_loadedInSession = false;
    UpdateUiState();
}

//  Process enumeration
static bool SnapshotProcesses(std::vector<ProcEntry>* out)
{
    out->clear();

    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        Log(L"CreateToolhelp32Snapshot failed: %lu", ::GetLastError());
        return false;
    }

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap, &pe))
    {
        do
        {
            ProcEntry e;
            e.pid     = pe.th32ProcessID;
            e.ppid    = pe.th32ParentProcessID;
            e.threads = pe.cntThreads;
            e.name    = pe.szExeFile;
            out->push_back(e);
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return true;
}

// Sort the cached snapshot according to the current column/direction.
static void ApplySort()
{
    const int  col = g_sortCol;
    const bool asc = g_sortAsc;

    std::sort(g_procs.begin(), g_procs.end(),
              [col, asc](const ProcEntry& a, const ProcEntry& b)
    {
        int c = 0;
        switch (col)
        {
        case 0:  c = (a.pid     < b.pid)     ? -1 : (a.pid     > b.pid     ? 1 : 0); break;
        case 2:  c = (a.ppid    < b.ppid)    ? -1 : (a.ppid    > b.ppid    ? 1 : 0); break;
        case 3:  c = (a.threads < b.threads) ? -1 : (a.threads > b.threads ? 1 : 0); break;
        case 1:
        default: c = _wcsicmp(a.name.c_str(), b.name.c_str()); break;
        }
        if (c == 0 && col != 0)                             // keep it deterministic
            c = (a.pid < b.pid) ? -1 : (a.pid > b.pid ? 1 : 0);
        return asc ? (c < 0) : (c > 0);
    });
}

// Rebuild the list view from g_procs (sorted, filtered).  
// The selection is preserved across rebuilds so refreshing or re-sorting keeps it intact.
static void ApplyFilter()
{
    if (!g_procView) return;

    // remember the current selection
    std::set<DWORD> selected;
    {
        int idx = -1;
        while ((idx = static_cast<int>(::SendMessageW(g_procView, LVM_GETNEXTITEM,
                                                      static_cast<WPARAM>(idx),
                                                      LVNI_SELECTED))) >= 0)
        {
            LVITEMW it = {};
            it.mask  = LVIF_PARAM;
            it.iItem = idx;
            if (::SendMessageW(g_procView, LVM_GETITEMW, 0, reinterpret_cast<LPARAM>(&it)))
                selected.insert(static_cast<DWORD>(it.lParam));
        }
    }

    ApplySort();

    std::wstring needle = GetText(g_filter);
    for (size_t i = 0; i < needle.size(); ++i) needle[i] = towlower(needle[i]);

    ::SendMessageW(g_procView, WM_SETREDRAW, FALSE, 0);
    ::SendMessageW(g_procView, LVM_DELETEALLITEMS, 0, 0);

    int row = 0;
    for (size_t i = 0; i < g_procs.size(); ++i)
    {
        const ProcEntry& e = g_procs[i];

        if (!needle.empty())
        {
            std::wstring hay = e.name;
            for (size_t k = 0; k < hay.size(); ++k) hay[k] = towlower(hay[k]);
            if (hay.find(needle) == std::wstring::npos) continue;
        }

        WCHAR pidTxt[24], ppidTxt[24], thrTxt[24];
        swprintf(pidTxt,  _countof(pidTxt),  L"%lu", e.pid);
        swprintf(ppidTxt, _countof(ppidTxt), L"%lu", e.ppid);
        swprintf(thrTxt,  _countof(thrTxt),  L"%lu", e.threads);

        LVITEMW it = {};
        it.mask     = LVIF_TEXT | LVIF_PARAM;
        it.iItem    = row;
        it.iSubItem = 0;
        it.pszText  = pidTxt;
        it.lParam   = static_cast<LPARAM>(e.pid);
        int idx = static_cast<int>(::SendMessageW(g_procView, LVM_INSERTITEMW, 0,
                                                  reinterpret_cast<LPARAM>(&it)));
        if (idx < 0) continue;

        LVITEMW sub = {};
        sub.mask     = LVIF_TEXT;
        sub.iItem    = idx;
        sub.iSubItem = 1;
        sub.pszText  = const_cast<LPWSTR>(e.name.c_str());
        ::SendMessageW(g_procView, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&sub));

        sub.iSubItem = 2;
        sub.pszText  = ppidTxt;
        ::SendMessageW(g_procView, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&sub));

        sub.iSubItem = 3;
        sub.pszText  = thrTxt;
        ::SendMessageW(g_procView, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&sub));

        // restore the selection
        if (!selected.empty() && selected.find(e.pid) != selected.end())
        {
            LVITEMW st = {};
            st.mask      = LVIF_STATE;
            st.state     = LVIS_SELECTED;
            st.stateMask = LVIS_SELECTED;
            ::SendMessageW(g_procView, LVM_SETITEMSTATE,
                           static_cast<WPARAM>(idx), reinterpret_cast<LPARAM>(&st));
        }

        ++row;
    }

    ::SendMessageW(g_procView, WM_SETREDRAW, TRUE, 0);
    ::InvalidateRect(g_procView, nullptr, TRUE);

    UpdateUiState();
}

static void RefreshProcessList()
{
    if (SnapshotProcesses(&g_procs))
        ApplyFilter();
}

// Number of rows currently selected (LVM_GETSELECTEDCOUNT).
static int SelectedItemCount()
{
    if (!g_procView) return 0;
    return static_cast<int>(::SendMessageW(g_procView, LVM_GETSELECTEDCOUNT, 0, 0));
}

// PIDs of every selected row, in list order.
static std::vector<DWORD> GetSelectedPids()
{
    std::vector<DWORD> pids;
    if (!g_procView) return pids;

    int idx = -1;
    while ((idx = static_cast<int>(::SendMessageW(g_procView, LVM_GETNEXTITEM,
                                                  static_cast<WPARAM>(idx), LVNI_SELECTED))) >= 0)
    {
        LVITEMW it = {};
        it.mask  = LVIF_PARAM;
        it.iItem = idx;
        if (::SendMessageW(g_procView, LVM_GETITEMW, 0, reinterpret_cast<LPARAM>(&it)))
            pids.push_back(static_cast<DWORD>(it.lParam));
    }
    return pids;
}

// Image name for a PID, from the cached snapshot (for readable log lines).
static std::wstring NameForPid(DWORD pid)
{
    for (size_t i = 0; i < g_procs.size(); ++i)
        if (g_procs[i].pid == pid) return g_procs[i].name;
    return std::wstring();
}

// sent once per selected process
static void TerminateSelection(HWND owner)
{
    if (g_device == INVALID_HANDLE_VALUE)
    {
        ::MessageBoxW(owner, L"The device is not attached - see the log.",
                      L"WasysProcKiller", MB_ICONINFORMATION);
        return;
    }

    std::vector<DWORD> pids = GetSelectedPids();
    if (pids.empty())
    {
        Log(L"nothing selected");
        return;
    }

    bool killsSelf = false;
    for (size_t i = 0; i < pids.size(); ++i)
        if (pids[i] == ::GetCurrentProcessId()) killsSelf = true;
    if (killsSelf &&
        ::MessageBoxW(owner, L"The selection contains this tool's own PID.\n"
                             L"Terminate anyway?",
                      L"WasysProcKiller", MB_YESNO | MB_ICONWARNING) != IDYES)
        return;

    int ok = 0, failed = 0;
    for (size_t i = 0; i < pids.size(); ++i)
    {
        DWORD pid = pids[i];
        if (pid == 0) { ++failed; continue; }          // Idle - nothing to open

        DWORD returned = 0;
        if (::DeviceIoControl(g_device, IOCTL_WASYS_TERMINATE_PROCESS,
                              &pid, WASYS_TERM_INPUT_SIZE,
                              nullptr, 0, &returned, nullptr))
        {
            ++ok;
            continue;
        }

        ++failed;
        DWORD e = ::GetLastError();
        std::wstring name = NameForPid(pid);
        Log(L"  %s(%lu) failed: 0x%08lX (%s)",
            name.empty() ? L"?" : name.c_str(), pid, e,
            wasys::Win32ErrText(e).c_str());
    }

    // One snapshot verifies the whole batch instead of one per PID.
    ::Sleep(250);
    std::vector<ProcEntry> after;
    std::wstring stillRunning;
    int alive = 0;
    if (SnapshotProcesses(&after))
    {
        std::set<DWORD> remaining;
        for (size_t i = 0; i < after.size(); ++i) remaining.insert(after[i].pid);

        for (size_t i = 0; i < pids.size(); ++i)
        {
            if (pids[i] == 0 || remaining.find(pids[i]) == remaining.end()) continue;
            ++alive;
            if (stillRunning.size() < 400)
            {
                if (!stillRunning.empty()) stillRunning += L", ";
                stillRunning += NameForPid(pids[i]) + L"(" + std::to_wstring(pids[i]) + L")";
            }
        }
    }

    if (alive)
        Log(L"%d terminated, %d failed, %d survivor(s): %s%s", ok, failed, alive,
            stillRunning.c_str(), stillRunning.size() >= 400 ? L" ..." : L"");
    else
        Log(L"%d terminated, %d failed", ok, failed);

    RefreshProcessList();
}

//  UI construction
static HWND Make(HWND parent, const WCHAR* cls, const WCHAR* text, DWORD style,
                 int x, int y, int w, int h, int id, HFONT font)
{
    HWND hw = ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
                                S(x), S(y), S(w), S(h),
                                parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                ::GetModuleHandleW(nullptr), nullptr);
    if (hw && font) ::SendMessageW(hw, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return hw;
}

static HWND Label(HWND p, const WCHAR* t, int x, int y, int w, int h)
{
    return Make(p, L"STATIC", t, SS_LEFT, x, y, w, h, -1, g_fontUi);
}

static void AddColumn(int idx, const WCHAR* title, int width)
{
    LVCOLUMNW c = {};
    c.mask     = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.iSubItem = idx;
    c.cx       = S(width);
    c.pszText  = const_cast<LPWSTR>(title);
    ::SendMessageW(g_procView, LVM_INSERTCOLUMNW, static_cast<WPARAM>(idx),
                   reinterpret_cast<LPARAM>(&c));
}

// Paint the little up/down arrow on the active column header.
static void UpdateSortArrows()
{
    for (int i = 0; i < 4; ++i)
    {
        LVCOLUMNW c = {};
        c.mask = LVCF_FMT;
        c.fmt  = LVCFMT_LEFT;
        if (i == g_sortCol)
            c.fmt |= (g_sortAsc ? HDF_SORTUP : HDF_SORTDOWN);
        ::SendMessageW(g_procView, LVM_SETCOLUMNW, static_cast<WPARAM>(i),
                       reinterpret_cast<LPARAM>(&c));
    }
}

static void CreateControls(HWND w)
{
    // filter + list
    Label(w, L"Filter", 8, 12, 32, 16);
    g_filter = Make(w, L"EDIT", L"", ES_AUTOHSCROLL | WS_BORDER,
                    44, 8, 404, 22, IDC_FILTER, g_fontUi);
    Make(w, L"BUTTON", L"Refresh", BS_PUSHBUTTON,
         456, 7, 96, 24, IDC_BTN_REFRESH, g_fontUi);

    g_procView = Make(w, L"SysListView32", L"",
                      WS_BORDER | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
                      8, 36, 544, 214, IDC_PROCVIEW, g_fontMono);
    ::SendMessageW(g_procView, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                   LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    AddColumn(0, L"PID",     60);
    AddColumn(1, L"Image",  300);
    AddColumn(2, L"PPID",    66);
    AddColumn(3, L"Threads", 66);
    UpdateSortArrows();

    // terminate the selected process(es)
    Make(w, L"BUTTON", L"Terminate selected process(es)", BS_PUSHBUTTON,
         332, 258, 220, 26, IDC_BTN_KILL, g_fontUi);

    // log
    Label(w, L"Log", 8, 292, 40, 16);
    g_log = Make(w, L"EDIT", L"",
                 WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                 8, 310, 544, 118, IDC_LOG, g_fontMono);
    ::SendMessageW(g_log, EM_SETLIMITTEXT, 0x7FFFFFFE, 0);
}

//  Window procedure
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        g_hwndMain = hwnd;
        CreateControls(hwnd);
        UpdateUiState();

        RefreshProcessList();

        // Automatic lifecycle: deploy the embedded driver, start it, attach.
        DeployDriverAndAttach();

        UpdateUiState();
        return 0;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC dc = reinterpret_cast<HDC>(wp);
        HWND ctl = reinterpret_cast<HWND>(lp);

        if (ctl == g_log)
        {
            ::SetTextColor(dc, RGB(0, 0, 0));
            ::SetBkColor(dc, RGB(255, 255, 255));
            return reinterpret_cast<LRESULT>(::GetStockObject(WHITE_BRUSH));
        }
        ::SetBkMode(dc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(::GetSysColorBrush(COLOR_BTNFACE));
    }

    case WM_NOTIFY:
    {
        LPNMHDR nh = reinterpret_cast<LPNMHDR>(lp);
        if (nh->idFrom != IDC_PROCVIEW) return 0;

        if (nh->code == LVN_ITEMCHANGED)
        {
            UpdateUiState();
        }
        else if (nh->code == LVN_COLUMNCLICK)
        {
            LPNMLISTVIEW nv = reinterpret_cast<LPNMLISTVIEW>(lp);
            if (nv->iSubItem >= 0 && nv->iSubItem < 4)
            {
                if (nv->iSubItem == g_sortCol)
                {
                    g_sortAsc = !g_sortAsc;         // same column -> flip
                }
                else
                {
                    g_sortCol = nv->iSubItem;
                    g_sortAsc = true;               // new column -> ascending
                }
                UpdateSortArrows();
                ApplyFilter();
            }
        }
        return 0;
    }

    case WM_COMMAND:
    {
        const int id   = LOWORD(wp);
        const int code = HIWORD(wp);

        switch (id)
        {
        case IDC_BTN_REFRESH:  RefreshProcessList();      break;
        case IDC_BTN_KILL:
            TerminateSelection(hwnd);
            break;
        case IDC_FILTER:
            if (code == EN_CHANGE) ApplyFilter();
            break;
        }
        return 0;
    }

    case WM_CLOSE:
        UnloadDriver();          // detach first, then stop/delete what we created
        ::DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hwnd, msg, wp, lp);
}

//  Entry point
int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int)
{
    using SetDpiAwarenessCtxFn = BOOL(WINAPI*)(void*);
    if (HMODULE user32 = ::GetModuleHandleW(L"user32.dll"))
    {
        auto p = reinterpret_cast<SetDpiAwarenessCtxFn>(
            ::GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (p) (void)p(reinterpret_cast<void*>(-4));   // PER_MONITOR_AWARE_V2
        else ::SetProcessDPIAware();
    }
    HDC screen = ::GetDC(nullptr);
    g_dpi = ::GetDeviceCaps(screen, LOGPIXELSX);
    ::ReleaseDC(nullptr, screen);
    if (g_dpi < 96) g_dpi = 96;

    g_driverPath = wasys::DefaultDriverPath();

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    ::InitCommonControlsEx(&icc);

    NONCLIENTMETRICSW ncm = {};
    ncm.cbSize = sizeof(ncm);
    if (::SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
        g_fontUi = ::CreateFontIndirectW(&ncm.lfMessageFont);
    if (!g_fontUi)
        g_fontUi = static_cast<HFONT>(::GetStockObject(DEFAULT_GUI_FONT));

    LOGFONTW lf = {};
    if (::GetObjectW(g_fontUi, sizeof(lf), &lf) == sizeof(lf))
    {
        lf.lfHeight = MulDiv(lf.lfHeight, 10, 9);
        CopyW(lf.lfFaceName, LF_FACESIZE, L"Consolas");
        lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
    }
    g_fontMono = ::CreateFontIndirectW(&lf);

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = inst;
    wc.hCursor       = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ::GetSysColorBrush(COLOR_BTNFACE);
    wc.lpszClassName = L"WasysProcKillerWnd";
    if (!::RegisterClassExW(&wc)) return 1;

    RECT rc = { 0, 0, S(kClientW), S(kClientH) };
    ::AdjustWindowRectEx(&rc, WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX), FALSE, 0);
    int ww = rc.right - rc.left;
    int wh = rc.bottom - rc.top;
    int x  = (::GetSystemMetrics(SM_CXSCREEN) - ww) / 2;
    int y  = (::GetSystemMetrics(SM_CYSCREEN) - wh) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;

    HWND hwnd = ::CreateWindowExW(0, wc.lpszClassName,
                                  L"WasysProcKiller",
                                  WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX),
                                  x, y, ww, wh, nullptr, nullptr, inst, nullptr);
    if (!hwnd) return 2;

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    MSG msg;
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        if (!::IsDialogMessageW(hwnd, &msg))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    }

    if (g_fontUi)   ::DeleteObject(g_fontUi);
    if (g_fontMono) ::DeleteObject(g_fontMono);
    return static_cast<int>(msg.wParam);
}
