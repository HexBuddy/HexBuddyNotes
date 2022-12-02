# Linux Commands Cheat Sheet

* [Linux Penetration Testing Commands](broken-reference)
  * [Linux Network Commands](broken-reference)
  * [System Information Commands](broken-reference)
    * [Redhat / CentOS / RPM Based Distros](broken-reference)
    * [YUM Commands](broken-reference)
    * [Debian / Ubuntu / .deb Based Distros](broken-reference)
  * [Linux User Management](broken-reference)
  * [Linux Decompression Commands](broken-reference)
  * [Linux Compression Commands](broken-reference)
  * [Linux File Commands](broken-reference)
  * [Samba Commands](broken-reference)
  * [Breaking Out of Limited Shells](broken-reference)
  * [Misc Commands](broken-reference)
  * [Linux File System Permissions](broken-reference)
  * [Linux File System](broken-reference)
  * [Linux Interesting Files / Dir’s](broken-reference)

A collection of hopefully useful Linux Commands for pen testers, this is not a complete list but a collection of commonly used commands + syntax as a sort of “cheatsheet”, this content will be constantly updated as I discover new awesomeness.

### Linux Penetration Testing Commands <a href="#linux-penetration-testing-commands" id="linux-penetration-testing-commands"></a>

The commands listed below are designed for local enumeration, typical commands a penetration tester would use during post exploitation or when performing command injection etc. See our pen test cheat sheet for an in depth list of pen testing tool commands and example usage.

#### Linux Network Commands <a href="#linux-network-commands" id="linux-network-commands"></a>

#### System Information Commands <a href="#system-information-commands" id="system-information-commands"></a>

Useful for local enumeration.

**Redhat / CentOS / RPM Based Distros**

**YUM Commands**

Package manager used by RPM based systems, you can pull some usefull information about installed packages and or install additional tools.

**Debian / Ubuntu / .deb Based Distros**

#### Linux User Management <a href="#linux-user-management" id="linux-user-management"></a>

#### Linux Decompression Commands <a href="#linux-decompression-commands" id="linux-decompression-commands"></a>

How to extract various archives (tar, zip, gzip, bzip2 etc) on Linux and some other tricks for searching inside of archives etc.

#### Linux Compression Commands <a href="#linux-compression-commands" id="linux-compression-commands"></a>

#### Linux File Commands <a href="#linux-file-commands" id="linux-file-commands"></a>

#### Samba Commands <a href="#samba-commands" id="samba-commands"></a>

Connect to a Samba share from Linux.

```
$ smbmount //server/share /mnt/win -o user=username,password=password1
$ smbclient -U user \\\\server\\share
$ mount -t cifs -o username=user,password=password //x.x.x.x/share /mnt/share
```

#### Breaking Out of Limited Shells <a href="#breaking-out-of-limited-shells" id="breaking-out-of-limited-shells"></a>

Credit to G0tmi1k for these (or wherever he stole them from!).

The Python trick:

```
python -c 'import pty;pty.spawn("/bin/bash")'
```

```
echo os.system('/bin/bash')
```

```
/bin/sh -i
```

#### Misc Commands <a href="#misc-commands" id="misc-commands"></a>

Clear bash history:

```
      $ ssh [email protected] | cat /dev/null > ~/.bash_history
    
```

#### Linux File System Permissions <a href="#linux-file-system-permissions" id="linux-file-system-permissions"></a>

#### Linux File System <a href="#linux-file-system" id="linux-file-system"></a>

#### Linux Interesting Files / Dir’s <a href="#linux-interesting-files--dirs" id="linux-interesting-files--dirs"></a>

Places that are worth a look if you are attempting to privilege escalate / perform post exploitation.
