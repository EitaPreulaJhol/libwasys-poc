# WasysProcKiller

A Windows GUI proof of concept for the process termination IOCTL in OPSWAT's `libwasys.sys`, the OESIS V4 helper driver. It embeds the driver in the executable, loads it as a kernel service, and terminates processes selected from a list.

## Background

Version 10.3.2951.0 of `libwasys.sys` creates the device `\Device\Wasys` and the DOS device link `\\.\WasysControl`. The device security descriptor is:

```
D:P(A;;GA;;;BU)(A;;GA;;;LS)(A;;GA;;;SY)
```

`BUILTIN\Users` gets `GENERIC_ALL`, so any local user can open the device and send it IOCTLs. The driver has no per-request caller check.

IOCTL `0x22E00C` (`METHOD_BUFFERED`, device type `0x22`) takes a 4-byte PID. The handler does this:

```c
PsLookupProcessByProcessId(pid, &Process);
ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE,
                      PsProcessType, KernelMode, &hProcess);
ZwCreateJobObject(&hJob, NULL, ...);
ZwAssignProcessToJobObject(hJob, hProcess);
ZwTerminateJobObject(hJob, 0);
```

This runs in kernel mode, so the caller's token does not decide which process can be opened. The target goes into a fresh job object and the job is terminated. Child processes started after the assignment inherit the job and are terminated with it. The KillerLand write-up reports that PPL-protected AV/EDR processes can be terminated the same way; the kernel-mode open is what makes that possible.

Credit for the original research goes to Jehad Abudagga ([@j3h4ck](https://x.com/j3h4ck)). The same primitive is published in [KillerLand](https://github.com/redteamfortress/KillerLand), and the sample is listed on [LOLDrivers](https://www.loldrivers.io/drivers/0f50f568-bd09-4d8a-a73d-d37bdd0a1cb6/). This repo is a separate implementation that adds a GUI and handles deployment and cleanup automatically. The reversing behind it was done on the 10.3.2951.0 build.

## What it does

- Reads `libwasys.sys` from an RCDATA resource and writes it to `C:\Windows\System32\drivers\wasyslab.sys`. That filename differs from the one OPSWAT installs so an existing installation is not overwritten.
- Creates a demand-start kernel service named `WasysLab` and starts it. If the service already exists and points at a different image, the tool stops and tells you to remove it first.
- Opens `\\.\WasysControl` and sends `0x22E00C` for each selected PID. If the selection contains the tool's own PID, it asks for confirmation.
- Takes a process snapshot 250 ms after the batch and logs which PIDs are still alive.
- On a normal window close, detaches from the device and undoes what it installed: stops the service if it started it, deletes the service and file if it created them. If the image is still mapped, deletion is scheduled for the next reboot.
- Compares the embedded image with the SHA-256 of the analyzed sample and logs a warning when they differ.

## Build

You need an x64 Windows machine with Visual Studio (2022 or 2026) and the Windows SDK. CMake 3.15 or newer if you want the CMake path.

The git tree doesn't include `libwasys.sys` or a compiled executable. Put the driver next to `build.bat` and check it first:

```
certutil -hashfile libwasys.sys SHA256
```

For the analyzed build the output should contain:

```
24a4dd32b633781c8c1193c9b445388ca7277799941a36ba9977b84382125e5c
```

Build from the project directory with the batch file:

```
build.bat
```

Or with CMake:

```
cmake -B build -A x64
cmake --build build --config Release
```

The resource script embeds whatever `libwasys.sys` sits in the project directory. The tool logs a warning at deploy time if the embedded hash does not match. It still runs.

## Usage

Run `WasysProcKiller.exe` as administrator. The manifest requests elevation, so Windows shows a UAC prompt. The PoC is unsigned and may trigger SmartScreen.

1. Find the target in the list.
2. Select one or more processes.
3. Click `Terminate selected process(es)`.
4. Check the log. Failed IOCTLs are logged with the Win32 error code.
5. Close the window when you are done so the tool can remove the service and file it created.

If the driver is already loaded when the tool starts, it attaches to the existing device and does not create or remove a service. If a `WasysLab` service exists but points somewhere else, the tool refuses to touch it.

The admin prompt is for the driver installation. The bug itself does not need admin: once the driver is loaded, any local user can open `\\.\WasysControl`. This GUI always elevates because it may have to create the service.

Killing `csrss.exe`, `smss.exe`, `wininit.exe`, `services.exe`, or `lsass.exe` will bugcheck the machine. Test in a VM or an controlled environment.

If you kill the tool after it installed the driver, the `WasysLab` service and `wasyslab.sys` remain. Remove them with:

```
sc stop WasysLab
sc delete WasysLab
del C:\Windows\System32\drivers\wasyslab.sys
```

The file may stay locked until the next reboot.

## Sample

| Field | Value |
| --- | --- |
| File | `libwasys.sys` |
| Product | OPSWAT OESIS V4 Helper Driver (x64) |
| Version | 10.3.2951.0 |
| SHA-256 | `24a4dd32b633781c8c1193c9b445388ca7277799941a36ba9977b84382125e5c` |
| MD5 | `faf0f09e10c49f78812d593674638ce2` |
| Signer | OPSWAT, Inc. Valid Authenticode signature with a Microsoft countersignature. |
| Device | `\\.\WasysControl` |
| IOCTL | `0x22E00C` |

## Scope

Only the termination path is implemented. The driver also exposes raw physical disk reads (`0x22E000`), deletion of locked files (`0x22E004`), registry writes (`0x22E008`), and port I/O (`0x22E010` and `0x22E014`).

## Detection notes

While the tool runs, it creates a kernel service named `WasysLab` with the image `C:\Windows\System32\drivers\wasyslab.sys` and the description `libwasys.sys lab harness (embedded driver)`. The System log usually records service creation as event 7045, and Sysmon event 6 records the driver load. The driver is validly signed by OPSWAT, so a signature check alone will not flag it. Look for OPSWAT-signed driver loads from unexpected paths or service names, and for handles to `\Device\Wasys` held by processes that are not part of an OPSWAT product.

## Credits

- Jehad Abudagga, [KillerLand](https://github.com/redteamfortress/KillerLand). Published the libwasys kill primitive and a PoC.
- [LOLDrivers entry](https://www.loldrivers.io/drivers/0f50f568-bd09-4d8a-a73d-d37bdd0a1cb6/), which lists the same SHA-256 and the handler behavior.

## Disclaimer

This is a kernel-assisted process termination primitive that bypasses user-mode access checks, including on processes that a normal user token cannot open. Use it only on systems you own or have written permission to test. The driver image belongs to OPSWAT and is not distributed in this repository. The code is provided as is, with no warranty. Do not run it on a production machine.
