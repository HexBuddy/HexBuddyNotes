# Anonforce

8 August 2020 4 minutes to read

[Link: https://tryhackme.com/room/bsidesgtanonforce](https://tryhackme.com/room/bsidesgtanonforce)

Another day, another CTF writeup from tryhackme. This is my second boot2root writeup series. The challenge is rather easier compared to the [first boot2root](https://deskel.github.io/posts/thm/library) write-up. Less tricky and straight forward. Without further ado, let’s get it on.

### Task 1: Capture the flag <a href="#task-1-capture-the-flag" id="task-1-capture-the-flag"></a>

As always, your task is to capture the user and the root flag.

#### Task 1-1: Capture user’s flag <a href="#task-1-1-capture-users-flag" id="task-1-1-capture-users-flag"></a>

First and foremost, launch your nmap scanner with the following command.

In a jiff, you will be presented two open ports, specifically Port 21 (FTP) and Port 22 (SSH). Let’s check the FTP port first.

OMG., who the hell put the entire system folder inside the FTP. In addition, everyone can access the FTP server. Moral of the story, direct the Anon user to a specific FTP directory (not the whole system) or secure the FTP with a password. Enough of that, let’s check the user flag inside the home directory.

That’s it, easy and straight forward.

#### Task 1-3: Capture the root’s flag <a href="#task-1-3-capture-the-roots-flag" id="task-1-3-capture-the-roots-flag"></a>

**1) The GPG**

There are tons of directory yet to be discovered. After a quick search, I come across an unusual filename called ‘notread’.

Inside the ‘notread’ directory, we have a PGP file and a private key. Download both files into your machine and let’s import the private key using the following command.

Uh-oh, guess we need a password to access the key. Maybe Mr.john can help us out, I mean John the Ripple (JtR). Without further ado, export the key into the hash and run JtR.

```
gpg2john private.asc > hash
john hash
```

The password for the private key is ‘xbox360’. After that, input the password to import the private key.

Then, decrypt the backup.pgp file using the following command.

Once again, you will be prompt with another password field. Now, enter the ‘xbox360’ password into the field.

**2) Crack the hash**

After decrypted the PGP file, a shadow file contains two users’ hashed password shown on the terminal.

```
root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::

melodias:$1$xDhc6S6G$IQHUW5ZtMkBQ5pUMjEQtL1:18120:0:99999:7:::
```

To identify the type of hashes, you can visit the hash [example list from hashcat](https://hashcat.net/wiki/doku.php?id=example\_hashes). After performing a quick search, the hash-name for the root user is ‘ sha512crypt $6$, SHA512 (Unix) 2 ‘ while the hash-name for user melodias is ‘ md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) 2 ‘ . Let’s do the hashcat crack using the following command.

```
hashcat64.exe -D 2 -m 1800 --hwmon-disable hash/hash.txt Dict/rockyou.txt
```

I am going to use my host computer to crack the hash because of the hashcat inside the kali VMware does not support the GPU processor. You can refer to my [previous write-up on hash cracking](https://www.embeddedhacker.com/2019/09/hacking-walkthrough-cracking-the-hashes/) for more detail.

After a few seconds, you will be prompted with the cracked password which is hikari (mean light in Japanese).

**3) Capture the flag**

Meanwhile, can we crack melodias’s hash? Nay, we can’t. A root password should be more than enough to solve this challenge. After that, log in to the root’s ssh shell using the following command.

Congratulation, you are now rooted in the machine. Let’s check for the flag.

### Conclusion <a href="#conclusion" id="conclusion"></a>

That’s it, we just finished our second boot2root challenge by stuxnet. Hope you learn something new today. See ya ;)

tags: _tryhackme_ - _CTF_ - _recon_ - _crack_

***

Thanks for reading. Follow my [twitter](https://twitter.com/DesKel5) for latest update

If you like this post, consider a small [donation](https://deskel.github.io/donate). Much appreciated. :)

***

#### Vortex



***
