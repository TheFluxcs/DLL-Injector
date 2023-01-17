using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Linq;
using System.Threading;
class Injector
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [Flags]
    enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;

    public static bool InjectDLL(int pid, string dllPath)
    {
        IntPtr hProc = OpenProcess(ProcessAccessFlags.All, false, pid);
        if (hProc == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open process!");
            return false;
        }

        IntPtr loadLibAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        if (loadLibAddr == IntPtr.Zero)
        {
            Console.WriteLine("Failed to find LoadLibraryA!");
            return false;
        }

        IntPtr dllPathAddr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)dllPath.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (dllPathAddr == IntPtr.Zero)
        {
            Console.WriteLine("Failed to allocate memory in target process!");
            return false;
        }
        int bytesWritten;
        bool success = WriteProcessMemory(hProc, dllPathAddr, Encoding.ASCII.GetBytes(dllPath), (uint)dllPath.Length, out bytesWritten);
        if (!success)
        {
            Console.WriteLine("Failed to write DLL path to target process memory!");
            return false;
        }
        IntPtr threadId;
        IntPtr threadHandle = CreateRemoteThread(hProc, IntPtr.Zero, 0, loadLibAddr, dllPathAddr, 0, out threadId);
        if (threadHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to create remote thread!");
            return false;
        }
        WaitForSingleObject(threadHandle, 5000);
        VirtualFreeEx(hProc, dllPathAddr, (uint)dllPath.Length, MEM_RESERVE);
        CloseHandle(hProc);
        return true;
    }
    static void Main(string[] args)
    {
        static int GetPidByProcessName(string processName)
        {
            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
            {
                return -1;
            }
            return processes[0].Id;
        }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[-] Important: The dll should be on desktop named: name.dll");
            Console.Write("Enter process name: ");
            string processName = Console.ReadLine();
            int pid = GetPidByProcessName(processName);
            if (pid == -1)
            {
                Console.WriteLine("Process not found.");
                Console.ReadKey();
                return;
            }
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string dllPath = Path.Combine(desktopPath, "name.dll");
            bool result = InjectDLL(pid, dllPath);
            if (result)
            {
                Console.WriteLine("DLL injected successfully!");
            }
            else
            {
                Console.WriteLine("Failed to inject DLL!");
            }
            Console.ReadKey();
    }         
}  

