using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;

namespace CsWhispers
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate uint MessageBoxA(
        IntPtr hWnd, 
        [MarshalAs(UnmanagedType.LPStr)] string lpText,
        [MarshalAs(UnmanagedType.LPStr)] string lpCaption, 
        uint uType
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate Boolean CreateProcessA(
        [MarshalAs(UnmanagedType.LPStr)] string lpApplicationName,
        [MarshalAs(UnmanagedType.LPStr)] string lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles,
        ProcessCreationFlags dwCreationFlags,
        IntPtr lpEnvironment,
        [MarshalAs(UnmanagedType.LPStr)] string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        ref PROCESS_INFORMATION lpProcessInformation
    );

    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
    [Flags]
    public enum ProcessCreationFlags : uint
    {
        ZERO_FLAG = 0x00000000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00001000,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        INHERIT_PARENT_AFFINITY = 0x00010000
    }
    internal class Program
    {
        static void Main(string[] args)
        {
            object[] mba_args = { IntPtr.Zero, "Hello from Dinvoke!", "WKLSEC",  (uint)0 };
            Generic.DynamicApiInvoke<uint>("user32.dll", "MessageBoxA", typeof(MessageBoxA), ref mba_args);


            STARTUPINFO si = default;
            PROCESS_INFORMATION pi = default;
            SECURITY_ATTRIBUTES lpa = default;
            SECURITY_ATTRIBUTES lta = default;

            object[] CreateProcessArgs = new object[] { null, @"C:\Windows\notepad.exe", lpa, lta, false, ProcessCreationFlags.ZERO_FLAG, IntPtr.Zero, null, si, pi };
            Generic.DynamicApiInvoke<bool>("kernel32.dll", "CreateProcessA", typeof(CreateProcessA), ref CreateProcessArgs);
            Console.WriteLine("Process handle before updating: 0x{0:X}", pi.hProcess);
            pi = (PROCESS_INFORMATION)CreateProcessArgs[9];
            Console.WriteLine("Process handle after updating: 0x{0:X}", pi.hProcess);

            unsafe
            {
                HANDLE pHandle = new HANDLE( (IntPtr)(-1) ) ;
                void* BaseAddress = (void*)0;
                uint RegionSize = 1024;
                NTSTATUS status = Syscalls.NtAllocateVirtualMemory(pHandle, &BaseAddress, (uint)0, &RegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                Console.WriteLine("Status: {0:X}", status);
                Console.WriteLine("Allocated to 0x{0:X}", (long)BaseAddress);

            }
        }
    }
}
