# Nmap Cheat Sheet

### Nmap Cheat Sheet

Reference guide for scanning networks with Nmap.

**Table of Contents**

1. [What is Nmap?](broken-reference)
2. [How to Use Nmap](broken-reference)
   1. [Command Line](broken-reference)
3. [Basic Scanning Techniques](broken-reference)
   1. [Scan a Single Target](broken-reference)
   2. [Scan Multiple Targets](broken-reference)
   3. [Scan a List of Targets](broken-reference)
   4. [Scan a Range of Hosts](broken-reference)
   5. [Scan an Entire Subnet](broken-reference)
   6. [Scan Random Hosts](broken-reference)
   7. [Exclude Targets From a Scan](broken-reference)
   8. [Exclude Targets Using a List](broken-reference)
   9. [Perform an Aggresive Scan](broken-reference)
   10. [Scan an IPv6 Target](broken-reference)
4. [Port Scanning Options](broken-reference)
   1. [Perform a Fast Scan](broken-reference)
   2. [Scan Specific Ports](broken-reference)
   3. [Scan Ports by Name](broken-reference)
   4. [Scan Ports by Protocol](broken-reference)
   5. [Scan All Ports](broken-reference)
   6. [Scan Top Ports](broken-reference)
   7. [Perform a Sequential Port Scan](broken-reference)
   8. [Attempt to Guess an Unknown OS](broken-reference)
   9. [Service Version Detection](broken-reference)
   10. [Troubleshoot Version Scan](broken-reference)
   11. [Perform a RPC Scan](broken-reference)
5. [Discovery Options](broken-reference)
   1. [Perform a Ping Only Scan](broken-reference)
   2. [Do Not Ping](broken-reference)
   3. [TCP SYN Ping](broken-reference)
   4. [TCP ACK Ping](broken-reference)
   5. [UDP Ping](broken-reference)
   6. [SCTP INIT Ping](broken-reference)
   7. [ICMP Echo Ping](broken-reference)
   8. [ICMP Timestamp Ping](broken-reference)
   9. [ICMP Address Mask Ping](broken-reference)
   10. [IP Protocol Ping](broken-reference)
   11. [ARP Ping](broken-reference)
   12. [Traceroute](broken-reference)
   13. [Force Reverse DNS Resolution](broken-reference)
   14. [Disable Reverse DNS Resolution](broken-reference)
   15. [Alternative DNS Lookup](broken-reference)
   16. [Manually Specify DNS Server](broken-reference)
   17. [Create a Host List](broken-reference)
6. [Firewall Evasion Techniques](broken-reference)
   1. [Fragment Packets](broken-reference)
   2. [Specify a Specific MTU](broken-reference)
   3. [Use a Decoy](broken-reference)
   4. [Idle Zombie Scan](broken-reference)
   5. [Manually Specify a Source Port](broken-reference)
   6. [Append Random Data](broken-reference)
   7. [Randomize Target Scan Order](broken-reference)
   8. [Spoof MAC Address](broken-reference)
   9. [Send Bad Checksums](broken-reference)
7. [Advanced Scanning Functions](broken-reference)
   1. [TCP SYN Scan](broken-reference)
   2. [TCP Connect Scan](broken-reference)
   3. [UDP Scan](broken-reference)
   4. [TCP NULL Scan](broken-reference)
   5. [TCP FIN Scan](broken-reference)
   6. [Xmas Scan](broken-reference)
   7. [TCP ACK Scan](broken-reference)
   8. [Custom TCP Scan](broken-reference)
   9. [IP Protocol Scan](broken-reference)
   10. [Send Raw Ethernet Packets](broken-reference)
   11. [Send IP Packets](broken-reference)
8. [Timing Options](broken-reference)
   1. [Timing Templates](broken-reference)
   2. [Set the Packet TTL](broken-reference)
   3. [Minimum Number of Parallel Operations](broken-reference)
   4. [Maximum Number of Parallel Operations](broken-reference)
   5. [Minimum Host Group Size](broken-reference)
   6. [Maximum Host Group Size](broken-reference)
   7. [Maximum RTT Timeout](broken-reference)
   8. [Initial RTT TImeout](broken-reference)
   9. [Maximum Number of Retries](broken-reference)
   10. [Host Timeout](broken-reference)
   11. [Minimum Scan Delay](broken-reference)
   12. [Maximum Scan Delay](broken-reference)
   13. [Minimum Packet Rate](broken-reference)
   14. [Maximum Packet Rate](broken-reference)
   15. [Defeat Reset Rate Limits](broken-reference)
9. [Output Options](broken-reference)
   1. [Save Output to a Text File](broken-reference)
   2. [Save Output to a XML File](broken-reference)
   3. [Grepable Output](broken-reference)
   4. [Output All Supported File Types](broken-reference)
   5. [Periodically Display Statistics](broken-reference)
   6. [1337 Output](broken-reference)
10. [Compare Scans](broken-reference)
    1. [Comparison Using Ndiff](broken-reference)
    2. [Ndiff Verbose Mode](broken-reference)
    3. [XML Output Mode](broken-reference)
11. [Troubleshooting and Debugging](broken-reference)
    1. [Get Help](broken-reference)
    2. [Display Nmap Version](broken-reference)
    3. [Verbose Output](broken-reference)
    4. [Debugging](broken-reference)
    5. [Display Port State Reason](broken-reference)
    6. [Only Display Open Ports](broken-reference)
    7. [Trace Packets](broken-reference)
    8. [Display Host Networking](broken-reference)
    9. [Specify a Network Interface](broken-reference)
12. Nmap Scripting Engine
    1. [Execute Individual Scripts](broken-reference)
    2. [Execute Multiple Scripts](broken-reference)
    3. [Execute Scripts by Category](broken-reference)
    4. [Execute Multiple Script Categories](broken-reference)
    5. [Troubleshoot Scripts](broken-reference)
    6. [Update the Script Database](broken-reference)

### What is Nmap?

Nmap ("Network Mapper") is a free and open source utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running. It was designed to rapidly scan large networks, but works fine against single hosts.

### How to Use Nmap

Nmap can be used in a variety of ways depending on the user's level of technical expertise.

| Technical Expertise | Usage                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------- |
| Beginner            | [Zenmap](https://nmap.org/zenmap/) the graphical user interface for Nmap               |
| Intermediate        | [Command line](https://nmap.org/)                                                      |
| Advanced            | Python scripting with the [Python-Nmap](https://pypi.org/project/python-nmap/) package |

#### Command Line

```
nmap [ <Scan Type> ...] [ <Options> ] { <target specification> }
```

### Basic Scanning Techniques

The `-s` switch determines the type of scan to perform.

| Nmap Switch | Description                 |
| ----------- | --------------------------- |
| **-sA**     | ACK scan                    |
| **-sF**     | FIN scan                    |
| **-sI**     | IDLE scan                   |
| **-sL**     | DNS scan (a.k.a. list scan) |
| **-sN**     | NULL scan                   |
| **-sO**     | Protocol scan               |
| **-sP**     | Ping scan                   |
| **-sR**     | RPC scan                    |
| **-sS**     | SYN scan                    |
| **-sT**     | TCP connect scan            |
| **-sW**     | Windows scan                |
| **-sX**     | XMAS scan                   |

#### Scan a Single Target

#### Scan Multiple Targets

```
nmap [target1, target2, etc]
```

#### Scan a List of Targets

#### Scan a Range of Hosts

```
nmap [range of IP addresses]
```

#### Scan an Entire Subnet

#### Scan Random Hosts

#### Exclude Targets From a Scan

```
nmap [targets] --exclude [targets]
```

#### Exclude Targets Using a List

```
nmap [targets] --excludefile [list.txt]
```

#### Perform an Aggresive Scan

#### Scan an IPv6 Target

### Port Scanning Options

#### Perform a Fast Scan

#### Scan Specific Ports

```
nmap -p [port(s)] [target]
```

#### Scan Ports by Name

```
nmap -p [port name(s)] [target]
```

#### Scan Ports by Protocol

```
nmap -sU -sT -p U:[ports],T:[ports] [target]
```

#### Scan All Ports

#### Scan Top Ports

```
nmap --top-ports [number] [target]
```

#### Perform a Sequential Port Scan

#### Attempt to Guess an Unknown OS

```
nmap -O --osscan-guess [target]
```

#### Service Version Detection

#### Troubleshoot Version Scan

```
nmap -sV --version-trace [target]
```

#### Perform a RPC Scan

### Discovery Options

**Host Discovery** The `-p` switch determines the type of ping to perform.

| Nmap Switch | Description |
| ----------- | ----------- |
| **-PI**     | ICMP ping   |
| **-Po**     | No ping     |
| **-PS**     | SYN ping    |
| **-PT**     | TCP ping    |

#### Perform a Ping Only Scan

#### Do Not Ping

#### TCP SYN Ping

#### TCP ACK Ping

#### UDP Ping

#### SCTP INIT Ping

#### ICMP Echo Ping

#### ICMP Timestamp Ping

#### ICMP Address Mask Ping

#### IP Protocol Ping

#### ARP ping

#### Traceroute

```
nmap --traceroute [target]
```

#### Force Reverse DNS Resolution

#### Disable Reverse DNS Resolution

#### Alternative DNS Lookup

```
nmap --system-dns [target]
```

#### Manually Specify DNS Server

Can specify a single server or multiple.

```
nmap --dns-servers [servers] [target]
```

#### Create a Host List

### Port Specification and Scan Order

### Service/Version Detection

| Nmap Switch | Description                  |
| ----------- | ---------------------------- |
| **-sV**     | Enumerates software versions |

### Script Scan

| Nmap Switch | Description             |
| ----------- | ----------------------- |
| **-sC**     | Run all default scripts |

### OS Detection

### Timing and Performance

The `-t` switch determines the speed and stealth performed.

| Nmap Switch | Description                 |
| ----------- | --------------------------- |
| **-T0**     | Serial, slowest scan        |
| **-T1**     | Serial, slow scan           |
| **-T2**     | Serial, normal speed scan   |
| **-T3**     | Parallel, normal speed scan |
| **-T4**     | Parallel, fast scan         |

Not specifying a `T` value will default to `-T3`, or normal speed.

### Firewall Evasion Techniques

#### Firewall/IDS Evasion and Spoofing

#### Fragment Packets

#### Specify a Specific MTU

```
nmap --mtu [MTU] [target]
```

#### Use a Decoy

```
nmap -D RND:[number] [target]
```

#### Idle Zombie Scan

```
nmap -sI [zombie] [target]
```

#### Manually Specify a Source Port

```
nmap --source-port [port] [target]
```

#### Append Random Data

```
nmap --data-length [size] [target]
```

#### Randomize Target Scan Order

```
nmap --randomize-hosts [target]
```

#### Spoof MAC Address

```
nmap --spoof-mac [MAC|0|vendor] [target]
```

#### Send Bad Checksums

### Advanced Scanning Functions

#### TCP SYN Scan

#### TCP Connect Scan

#### UDP Scan

#### TCP NULL Scan

#### TCP FIN Scan

#### Xmas Scan

#### TCP ACK Scan

#### Custom TCP Scan

```
nmap --scanflags [flags] [target]
```

#### IP Protocol Scan

#### Send Raw Ethernet Packets

#### Send IP Packets

### Timing Options

#### Timing Templates

#### Set the Packet TTL

```
nmap --ttl [time] [target]
```

#### Minimum NUmber of Parallel Operations

```
nmap --min-parallelism [number] [target]
```

#### Maximum Number of Parallel Operations

```
nmap --max-parallelism [number] [target]
```

#### Minimum Host Group Size

```
nmap --min-hostgroup [number] [targets]
```

#### Maximum Host Group Size

```
nmap --max-hostgroup [number] [targets]
```

#### Maximum RTT Timeout

```
nmap --initial-rtt-timeout [time] [target]
```

#### Initial RTT Timeout

```
nmap --max-rtt-timeout [TTL] [target]
```

#### Maximum Number of Retries

```
nmap --max-retries [number] [target]
```

#### Host Timeout

```
nmap --host-timeout [time] [target]
```

#### Minimum Scan Delay

```
nmap --scan-delay [time] [target]
```

#### Maxmimum Scan Delay

```
nmap --max-scan-delay [time] [target]
```

#### Minimum Packet Rate

```
nmap --min-rate [number] [target]
```

#### Maximum Packet Rate

```
nmap --max-rate [number] [target]
```

#### Defeat Reset Rate Limits

```
nmap --defeat-rst-ratelimit [target]
```

### Output Options

| Nmap Switch | Description                                  |
| ----------- | -------------------------------------------- |
| `-oN`       | Normal output                                |
| `-oX`       | XML output                                   |
| `-oA`       | Normal, XML, and Grepable format all at once |

#### Save Output to a Text File

```
nmap -oN [scan.txt] [target]
```

#### Save Output to a XML File

```
nmap -oX [scan.xml] [target]
```

#### Grepable Output

```
nmap -oG [scan.txt] [target]
```

#### Output All Supported File Types

```
nmap -oA [path/filename] [target]
```

#### Periodically Display Statistics

```
nmap --stats-every [time] [target]
```

#### 1337 Output

```
nmap -oS [scan.txt] [target]
```

### Compare Scans

#### Comparison Using Ndiff

```
ndiff [scan1.xml] [scan2.xml]
```

#### Ndiff Verbose Mode

```
ndiff -v [scan1.xml] [scan2.xml]
```

#### XML Output Mode

```
ndiff --xml [scan1.xml] [scan2.xml]
```

### Troubleshooting and Debugging

#### Get Help

#### Display Nmap Version

#### Verbose Output

#### Debugging

#### Display Port State Reason

#### Only Display Open Ports

#### Trace Packets

```
nmap --packet-trace [target]
```

#### Display Host Networking

#### Specify a Network Interface

```
nmap -e [interface] [target]
```

### Nmap Scripting Engine

#### Execute Individual Scripts

```
nmap --script [script.nse] [target]
```

#### Execute Multiple Scripts

```
nmap --script [expression] [target]
```

#### Execute Scripts by Category

```
nmap --script [category] [target]
```

#### Execute Multiple Script Categories

```
nmap --script [category1,category2,etc]
```

#### Troubleshoot Scripts

```
nmap --script [script] --script-trace [target]
```

#### Update the Script Database

**Reference Sites**

* [Nmap - The Basics](https://www.youtube.com/watch?v=\_JvtO-oe8k8)
* [Reference link 1](https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/)
* [Beginner's Guide to Nmap](https://www.linux.com/learn/beginners-guide-nmap)
* [Top 32 Nmap Command](https://www.cyberciti.biz/security/nmap-command-examples-tutorials/)
* [Nmap Linux man page](https://linux.die.net/man/1/nmap)
* [29 Practical Examples of Nmap Commands](https://www.tecmint.com/nmap-command-examples/)
* [Nmap Scanning Types, Scanning Commands , NSE Scripts](https://medium.com/@infosecsanyam/nmap-cheat-sheet-nmap-scanning-types-scanning-commands-nse-scripts-868a7bd7f692)
* [Nmap CheatSheet](https://www.cheatography.com/netwrkspider/cheat-sheets/nmap-cheatsheet/)
* [Nmap Cheat Sheet](https://highon.coffee/blog/nmap-cheat-sheet/)
* [Nmap Cheat Sheet: From Discovery to Exploits](https://resources.infosecinstitute.com/nmap-cheat-sheet/)
* [Nmap: my own cheatsheet](https://www.andreafortuna.org/2018/03/12/nmap-my-own-cheatsheet/)
* [NMAP Commands Cheatsheet](https://hackersonlineclub.com/nmap-commands-cheatsheet/)
* [Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)
* [Nmap Cheat Sheet](http://nmapcookbook.blogspot.com/2010/02/nmap-cheat-sheet.html)
