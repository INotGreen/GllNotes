



## 动态加载C#代码

```C#
using Microsoft.CSharp;
using System;
using System.CodeDom.Compiler;


public class DynamicCompiler
{
    public static void Main()
    {
        string code = Test3.Properties.Resources.String2;

        CSharpCodeProvider provider = new CSharpCodeProvider();
        CompilerParameters parameters = new CompilerParameters();

        // Generate an executable instead of a DLL
        parameters.GenerateExecutable = false;

        // Generate in memory
        parameters.GenerateInMemory = true;

        CompilerResults results = provider.CompileAssemblyFromSource(parameters, code);

        if (results.Errors.HasErrors)
        {
            Console.WriteLine("Compilation errors:");
            foreach (CompilerError error in results.Errors)
            {
                Console.WriteLine(error.ErrorText);
            }
        }
        else
        {
            var assembly = results.CompiledAssembly;
            var programType = assembly.GetType("Program");
            var method = programType.GetMethod("Main");
            method.Invoke(null, null);
        }
        while(true);
    }
}

```



## 1.whoami /groups

```C#
using System;
using System.Security.Principal;

class Program
{
    static void Main()
    {
        WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
        Console.WriteLine("Group Information\n-----------------\n");
        Console.WriteLine("{0,-45} {1,-10} {2,-45} {3}", "Group Name", "Type", "SID", "Attributes\n");
        Console.WriteLine(new string('=', 120));

        foreach (IdentityReference group in currentUser.Groups)
        {
            try
            {
                SecurityIdentifier sid = group as SecurityIdentifier;
                NTAccount ntAccount = sid.Translate(typeof(NTAccount)) as NTAccount;
                string groupName = ntAccount != null ? ntAccount.ToString() : "Unknown";
                string groupType = GetGroupType(sid);
                string attributes = GetGroupAttributes(sid);

                Console.WriteLine(String.Format("{0,-45} {1,-10} {2,-45} {3}", groupName, groupType, sid.ToString(), attributes));
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error processing group {0}: {1}", group.ToString(), ex.Message));
            }
        }
    }

    static string GetGroupType(SecurityIdentifier sid)
    {
        // Simplified logic based on SID prefixes
        string sidValue = sid.Value;
        if (sidValue.StartsWith("S-1-5-32"))
            return "别名";
        if (sidValue.StartsWith("S-1-5-21"))
            return "已知组";
        if (sidValue.StartsWith("S-1-5-"))
            return "本地";
        if (sidValue.StartsWith("S-1-16-"))
            return "标签";
        return "未知";
    }

    static string GetGroupAttributes(SecurityIdentifier sid)
    {
        // This is a simplified version; actual logic might be more complex
        return "必需的组, 启用于默认, 启用 的组";
    }
}

```

## 2.whoami /priv

```C#
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    // Windows API constants and structures
    private const uint TOKEN_QUERY = 0x0008;
    private const int SE_PRIVILEGE_ENABLED = 0x00000002;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName);


    private enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        MaxTokenInfoClass
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    static void Main()
    {
        IntPtr tokenHandle;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out tokenHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        try
        {
            int size = 0;
            GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out size);
            IntPtr buffer = Marshal.AllocHGlobal(size);

            try
            {
                if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, buffer, size, out size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                TOKEN_PRIVILEGES privileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(buffer, typeof(TOKEN_PRIVILEGES));
                Console.WriteLine("特权信息\n----------------------\n");
                Console.WriteLine("{0,-35} {1,-40} {2,-10}", "特权名", "描述", "状态");
                Console.WriteLine("=================================== ======================================== =========");

                for (int i = 0; i < privileges.PrivilegeCount; i++)
                {
                    LUID_AND_ATTRIBUTES la = privileges.Privileges[i];
                    StringBuilder name = new StringBuilder(512);
                    int nameLength = name.Capacity;
                    IntPtr luidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LUID)));
                    Marshal.StructureToPtr(la.Luid, luidPtr, false);

                    if (LookupPrivilegeName(null, luidPtr, name, ref nameLength))
                    {
                        string privilegeName = name.ToString();
                        string description = GetPrivilegeDescription(privilegeName);
                        string status = (la.Attributes & SE_PRIVILEGE_ENABLED) != 0 ? "已启用" : "已禁用";
                        Console.WriteLine("{0,-35} {1,-40} {2,-10}", privilegeName, description, status);
                    }

                    Marshal.FreeHGlobal(luidPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseHandle(tokenHandle);
        }
    }

    private static string GetPrivilegeDescription(string privilegeName)
    {
        switch (privilegeName)
        {
            case "SeShutdownPrivilege":
                return "关闭系统";
            case "SeChangeNotifyPrivilege":
                return "绕过遍历检查";
            case "SeUndockPrivilege":
                return "从扩展坞上取下计算机";
            case "SeIncreaseWorkingSetPrivilege":
                return "增加进程工作集";
            case "SeTimeZonePrivilege":
                return "更改时区";
            default:
                return "未知特权";
        }
    }
}

```

## 3.whoami

```C#
using System;
using System.Security.Principal;

class Program
{
    static void Main()
    {
        try
        {
            // 获取当前用户的 Windows 身份
            WindowsIdentity currentUser = WindowsIdentity.GetCurrent();

            // 打印当前用户名
            Console.WriteLine("Current User: " + currentUser.Name);

            // 打印用户的域
            if (currentUser.User.AccountDomainSid != null)
            {
                SecurityIdentifier sid = currentUser.User.AccountDomainSid;
                var account = (NTAccount)sid.Translate(typeof(NTAccount));
                Console.WriteLine("Domain: " + account.Value.Split('\\')[0]);
            }
            else
            {
                Console.WriteLine("Local User: " + currentUser.Name);
            }

            // 打印用户的SID
            Console.WriteLine("User SID: " + currentUser.User.Value);
        }
        catch (Exception ex) { return; }
    }
}

```

## 4.systeminfo

```C#
using System;
using System.Management;

class Program
{
    static void Main()
    {
        Console.WriteLine("主机名: " + Environment.MachineName);
        Console.WriteLine("\n系统信息");
        Console.WriteLine(new string('-', 20));

        // 查询操作系统基本信息
        GetOperatingSystemInfo();

        // 查询系统制造商、型号等
        Console.WriteLine("\n系统硬件信息");
        Console.WriteLine(new string('-', 20));
        GetSystemManufacturer();

        // 查询处理器信息
        Console.WriteLine("\n处理器信息");
        Console.WriteLine(new string('-', 20));
        GetProcessorInfo();

        // 查询内存信息
        Console.WriteLine("\n内存信息");
        Console.WriteLine(new string('-', 20));
        GetMemoryInfo();

        // 查询磁盘信息
        Console.WriteLine("\n磁盘信息");
        Console.WriteLine(new string('-', 20));
        GetDiskInfo();

        // 查询网络适配器信息
        Console.WriteLine("\n网络适配器信息");
        Console.WriteLine(new string('-', 20));
        GetNetworkInfo();

        // 查询Hyper-V支持信息
        Console.WriteLine("\nHyper-V 配置要求");
        Console.WriteLine(new string('-', 20));
        GetHyperVRequirements();

        // 查询修补程序信息
        Console.WriteLine("\n已安装的修补程序");
        Console.WriteLine(new string('-', 20));
        GetPatches();

        Console.WriteLine("\n按任意键继续...");
        Console.ReadKey();
    }
    static void GetPatches()
    {
        Console.WriteLine("修补程序:");
        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_QuickFixEngineering"))
        {
            foreach (ManagementObject patch in searcher.Get())
            {
                Console.WriteLine($"  [{patch["HotFixID"]}]: {patch["Description"]} - Installed on {patch["InstalledOn"]}");
            }
        }
    }

    static void GetOperatingSystemInfo()
    {
        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
        {
            foreach (ManagementObject os in searcher.Get())
            {
                Console.WriteLine("OS 名称: " + SafeGetProperty(os, "Caption"));
                Console.WriteLine("OS 版本: " + SafeGetProperty(os, "Version") + " Build " + SafeGetProperty(os, "BuildNumber"));
                Console.WriteLine("OS 制造商: " + SafeGetProperty(os, "Manufacturer"));
                Console.WriteLine("系统启动时间: " + ManagementDateTimeConverter.ToDateTime(SafeGetProperty(os, "LastBootUpTime")).ToString());
            }
        }
    }

    static string SafeGetProperty(ManagementObject obj, string propertyName)
    {
        // 检查属性是否存在并返回相应的值或默认值
        return obj.Properties[propertyName]?.Value?.ToString() ?? "未知";
    }

    static void GetSystemManufacturer()
    {
        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
        {
            foreach (var obj in searcher.Get())
            {
                Console.WriteLine("制造商: " + obj["Manufacturer"]);
                Console.WriteLine("型号: " + obj["Model"]);
                Console.WriteLine("系统类型: " + obj["SystemType"]);
                Console.WriteLine("物理内存总量: " + Convert.ToInt64(obj["TotalPhysicalMemory"]) / 1024 / 1024 + " MB");
                Console.WriteLine("域: " + obj["Domain"]);  // 确保此行正确无误
                Console.WriteLine("部分加入域: " + obj["PartOfDomain"]);  // 显示是否加入域
            }
        }
    }


    static void GetProcessorInfo()
    {
        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
        {
            foreach (var obj in searcher.Get())
            {
                Console.WriteLine("处理器: " + obj["Name"]);
                Console.WriteLine("描述: " + obj["Description"]);
                Console.WriteLine("处理器ID: " + obj["ProcessorId"]);
                Console.WriteLine("核心数: " + obj["NumberOfCores"]);
            }
        }
    }
    static void GetMemoryInfo()
    {
        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemory"))
        {
            foreach (var obj in searcher.Get())
            {
                Console.WriteLine("内存设备: " + obj["DeviceLocator"]);
                Console.WriteLine("内存容量: " + Math.Round(Convert.ToDouble(obj["Capacity"]) / 1024 / 1024 / 1024, 2) + " GB");
                Console.WriteLine("速度: " + obj["Speed"] + " MHz");
            }
        }
    }


    static void GetDiskInfo()
    {
        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
        {
            foreach (var obj in searcher.Get())
            {
                Console.WriteLine("磁盘型号: " + obj["Model"]);
                Console.WriteLine("磁盘接口类型: " + obj["InterfaceType"]);
                Console.WriteLine("磁盘容量: " + Math.Round(Convert.ToDouble(obj["Size"]) / 1024 / 1024 / 1024, 2) + " GB");
            }
        }
    }

    static void GetNetworkInfo()
    {
        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID IS NOT NULL"))
        {
            foreach (var obj in searcher.Get())
            {
                Console.WriteLine("网络适配器名称: " + obj["NetConnectionID"]);
                Console.WriteLine("描述: " + obj["Description"]);
                Console.WriteLine("状态: " + obj["Status"]);
                Console.WriteLine("速度: " + Convert.ToInt64(obj["Speed"]) / 1000 / 1000 + " Mbps");
            }
        }
    }


    static void GetHyperVRequirements()
    {
        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
        {
            foreach (var obj in searcher.Get())
            {
                Console.WriteLine("虚拟机监视器模式扩展: " + SafeGetProperty((ManagementObject)obj, "VirtualizationFirmwareEnabled"));
                Console.WriteLine("二级地址转换: " + SafeGetProperty((ManagementObject)obj, "SecondLevelAddressTranslationExtensions"));
                //Console.WriteLine("数据执行保护可用: " + SafeGetProperty((ManagementObject)obj, "DataExecutionPreventionAvailable"));
            }
        }
    }
}

```

## 5.ipconfig /all

```

```

## 6.ls

```C#
using System;
using System.IO;

class Program
{
    static void Main(string[] args)
    {
        // 获取当前工作目录，或者从命令行参数获取指定目录
        string path = args.Length > 0 ? args[0] : Directory.GetCurrentDirectory();

        // 列出指定目录下的所有文件和子目录
        ListDirectoryContents(path);
    }

    static void ListDirectoryContents(string path)
    {
        try
        {
            // 获取目录信息
            DirectoryInfo dirInfo = new DirectoryInfo(path);
            FileSystemInfo[] files = dirInfo.GetFileSystemInfos();

            // 表头
            Console.WriteLine("{0,-10} {1,-25} {2,-10} {3}", "Mode", "LastWriteTime", "Length", "Name");
            Console.WriteLine(new string('-', 70));

            foreach (FileSystemInfo file in files)
            {
                string mode = GetFileMode(file);
                string lastWriteTime = file.LastWriteTime.ToString("yyyy/M/dd    HH:mm");
                string length = file is FileInfo fileInfo ? fileInfo.Length.ToString() : "";
                string name = file.Name;

                Console.WriteLine("{0,-10} {1,-25} {2,10} {3}", mode, lastWriteTime, length, name);
            }
        }
        catch (IOException ex)
        {
            Console.WriteLine($"An error occurred while accessing {path}: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"Permission denied: {ex.Message}");
        }
    }

    static string GetFileMode(FileSystemInfo fileInfo)
    {
        FileAttributes attributes = fileInfo.Attributes;
        string mode = (attributes & FileAttributes.Directory) == FileAttributes.Directory ? "d" : "-";
        mode += (attributes & FileAttributes.Archive) == FileAttributes.Archive ? "a" : "-";
        mode += (attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly ? "r" : "-";
        mode += (attributes & FileAttributes.Hidden) == FileAttributes.Hidden ? "h" : "-";
        mode += (attributes & FileAttributes.System) == FileAttributes.System ? "s" : "-";

        return mode;
    }

}

```

## 7.ps

```C#
using System;
using System.Diagnostics;

public class Program
{
   public static void Main()
    {
        // 标题行，设定合适的列宽和对齐方式
        Console.WriteLine("{0,-10} {1,-35} {2,15}", "PID", "Process Name", "Memory Usage (MB)");

        // 获取所有进程
        Process[] processList = Process.GetProcesses();

        foreach (Process process in processList)
        {
            try
            {
                // 输出进程信息，注意内存使用量的对齐（右对齐），并确保MB后有足够空间
                Console.WriteLine("{0,-10} {1,-35} {2,15:N2} MB",
                    process.Id,
                    process.ProcessName,
                    process.PrivateMemorySize64 / 1024.0 / 1024.0); // 使用浮点运算确保精度，格式化为两位小数
            }
            catch (Exception ex)
            {
                // 某些进程可能无法访问某些信息，需要处理异常
                Console.WriteLine($"Error accessing process {process.ProcessName}: {ex.Message}");
            }
        }
    }
}

```

