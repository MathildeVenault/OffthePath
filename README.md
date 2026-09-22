# Off the Path injection 

This repository implements one of the new techniques of process injection dubbed as "the Off the Path", presented at the Korean conference POC 2026.

## What it is 

The Off the Path techniques abuse the mechanisms used to resolve the path of a module loaded LoadLibrary(). This can be either a Windows API acting as a "Path Builder" (ie: GetSystemDirectory(), GetModuleFileName(), etc.) or directly the internal resolution mechanisms of LoadLibrary(), when the argument provided is only the module name (ie: LoadLibrary("shell32.dll")).

In this repository, we're hijacking `GetSystemDirectory()`, so the API returns a directory of our choosing instead of the default `"C:\Windows\System32"`. Please note that GetSystemDirectory() is only one of the many ways a process can resolve a path, hence only one member of the Off the Path injection family.

## How it works

Let's consider a process that performs the following:

```
DllDirectory[MAX_PATH] = "";
DllFullPath[MAX_PATH] = "";

GetSystemDirectory(DllDirectory, sizeof(DllDirectory));

DllFullPath = append(DllDirectory, "mydll.dll");

LoadLibrary(DllFullPath);
```

Under the hood, `GetSystemDirectory()` relies on a global variable called `KernelBaseGlobalData` (`KBGD`), that lives in `KernelBase.dll`. 

As `KernelBase.dll` is mapped as a shared image section across all processes in a Windows session, the address of `KernelBaseGlobalData` is identical in every process. In addition, there is an undocumented API, `KernelBaseGetGlobalData()` that can retrieve the address of that global variable. This means adversaries can determine the address of all process' `KBGD` variables using in their own process the API `KernelBaseGetGlobalData()`. With the `KBGD` address in hands, adversaries can open a handle with write access on a remote process and and patch their local `KBGD` variable, so that `GetSystemDirectory()` returns the patched value next time the API is called. Subsequently, the hijacked path will cause `LoadLibrary()` to attempt to load the module from the hijacked location:

```
DllDirectory[MAX_PATH] = "";
DllFullPath[MAX_PATH] = "";

// FakeDirectory receives the overwritten value of KBGD
GetSystemDirectory(FakeDirectory, sizeof(DllDirectory));

FakeDllFullPath = append(FakeDirectory, "mydll.dll");

LoadLibrary(FakeDllFullPath);
```

## Demo 

For demo purposes, we are targeting explorer.exe. When a new File Explorer window is opened, `explorer.exe` uses `GetSystemDirectory()` to determine the location of the module `xmllite.dll`. By default, the POC targets explorer.exe and patches its KBGD so that `GetSystemDirectory()` returns `C:\malicious`. 
### Setup

1/ Open `OffthePath.sln` in Visual Studio 2022 & compile the two projects:
- `OffthePath` - the main tool (outputs to `bin\x64\Release\`)
- `TestPayload` - the demo DLL (outputs to `payload\xmllite.dll`)

Both are configured for x64 Release builds only.

2/ Create the repository designated to contain the mock `xmllite.dll`: 
```cmd
mkdir C:\malicious
```

3/ Copy your mock `xmllite.dll` into that repository:
```
copy payload\xmllite.dll
```

### Usage

1/ Execute the process injection:
```cmd
# Default: targets explorer.exe with C:\malicious\
OffthePath.exe

# Custom target
OffthePath.exe --target notepad.exe --path C:\evil\

# By PID
OffthePath.exe --pid 1234 --path C:\evil\
```

2/ Trigger the load of the DLL on your target. For explorer.exe,  open a new window. If you're using our sample DLL, you should see a Message Box popping up to confirm the success of the injection.
