---
description: 'Tag : Web'
---

# Nikto

### Introduction:

In this post, you will learn what is nikto and how does it work and a full command tutorial and by end of this post, you will be more familiar with the tool.

### What is Nikto 🤔

Nikto is a web-based vulnerability scanner, It is open-source software written in Perl language. The primary target of the tools is to do vulnerability scanning.

This tool scans 6,800 vulnerabilities that are commonly available on the sites. The tool also scans 250 platforms from an unpatched site. Also finds some vulnerability in the webserver files. I will use this tool very often, Mostly this tool will be caught in IDS (Intrusion detection sensor) or IPS (Intrusion Prevention sensor).

Also Read: [Zenmap full tutorial](https://www.techyrick.com/zenmap/)

There are some alternative tools such as Metasploit, comparing to Metasploit, Nikto is the best tool. Bug bounty hunters use this tool a lot and even hackers use this tool.

### Who developed the nikto tool 🔻

The tool was developed by Chris Sullo & David Lodge and I wonder how they kept the logo for this tool. And I am in love with this logo. Below are the links to the tool 👇🏽

### Features in nikto tool

1. SSL Support (Unix with OpenSSL or maybe Windows with ActiveState’s
2. Perl/NetSSL)
3. Full HTTP proxy support
4. Checks for outdated server components
5. Save reports in plain text, XML, HTML, NBE or CSV
6. Template engine to easily customize reports
7. Scan multiple ports on a server, or multiple servers via input file (including nmap output)
8. LibWhisker’s IDS encoding techniques
9. Easily updated via command line
10. Identifies installed software via headers, favicons and files
11. Host authentication with Basic and NTLM
12. Subdomain guessing
13. Apache and cgiwrap username enumeration
14. Mutation techniques to “fish” for content on web servers
15. Scan tuning to include or exclude entire classes of vulnerability
16. checks
17. Guess credentials for authorization realms (including many default id/pw combos)
18. Authorization guessing handles any directory, not just the root
19. directory
20. Enhanced false positive reduction via multiple methods: headers,
21. page content, and content hashing
22. Reports “unusual” headers seen
23. Interactive status, pause and changes to verbosity settings
24. Save full request/response for positive tests
25. Replay saved positive requests
26. Maximum execution time per target
27. Auto-pause at a specified time
28. Checks for common “parking” sites

### Useful commands in Nikto tool ✔👇

\-config+ :Use this config file\
\-Display+ :Turn on/off display outputs\
\-dbcheck : check the database and other key files for syntax errors\
\-Format+ :save file (-o) format\
\-Help : Extended help information\
\-host+ :target host/URL\
\-id+ : Host authentication to use, the format is id: pass or id:pass: realm\
\-output+:Write output to this file\
\-nossl : Disables using SSL\
\-no404 : Disables 404 checks\
\-Plugins+ :List of plugins to run (default: ALL)\
\-port+ :Port to use (default 80)\
\-root+ :Prepend root value to all requests, the format is /directory\
\-ssl : Force SSL mode on port\
\-timeout+ :Timeout for requests (default 10 seconds)

### How to work with the Nikto tool ❓

Just follow the below example and I am sure by end of this post you will be familiar with the tool and If you need any additional information on the Nikto tool then watch the YT video at the top.

#### Example1:

Installing the Nikto tool

<pre><code><strong>sudo apt-get install nikto
</strong></code></pre>

<figure><img src="https://www.techyrick.com/wp-content/uploads/2021/09/2021-09-26-18_51_44-Debian-10.x-64-bit-VMware-Workstation-16-Player-Non-commercial-use-only.webp" alt="installing tool"><figcaption></figcaption></figure>

#### Example2:

Let’s do a standard scan in nikto, which is directly scanning the target

<pre><code><strong>nikto -h &#x3C;IP/domain>
</strong></code></pre>

<pre><code><strong>nikto -h example.com
</strong></code></pre>

<figure><img src="https://www.techyrick.com/wp-content/uploads/2021/09/2021-09-26-18_54_38-Debian-10.x-64-bit-VMware-Workstation-16-Player-Non-commercial-use-only-1024x377.webp" alt="nikto scan"><figcaption></figcaption></figure>

\*Sorry about the scan it is nikto.com, you can enter your own target

#### Example3:

Running a scan on target SSL or TLS

<pre><code><strong>nikto -h example.com -ssl
</strong></code></pre>

<figure><img src="https://www.techyrick.com/wp-content/uploads/2021/09/2021-09-26-19_08_22-Debian-10.x-64-bit-VMware-Workstation-16-Player-Non-commercial-use-only.webp" alt="ssl scan"><figcaption></figcaption></figure>



#### Example4:

Scanning specific port on nikto

<pre><code><strong>nikto -h example.com -port 80
</strong></code></pre>

<figure><img src="https://www.techyrick.com/wp-content/uploads/2021/09/2021-09-26-19_21_28-Debian-10.x-64-bit-VMware-Workstation-16-Player-Non-commercial-use-only.webp" alt="scanning vulnerabilities"><figcaption></figcaption></figure>

#### Example5:

Saving the scan in an output

<pre><code><strong>nikto -h example.com -output /Downloads/file.txt
</strong></code></pre>

You can specify the path you want

<figure><img src="https://www.techyrick.com/wp-content/uploads/2021/09/2021-09-26-19_30_27-Debian-10.x-64-bit-VMware-Workstation-16-Player-Non-commercial-use-only.webp" alt="nikto"><figcaption></figcaption></figure>

#### Example6:

Scanning anonymously using Nikto is very easy just add proxychains in front of the command

<pre><code><strong>proxychains nikto -h example.com 
</strong></code></pre>

<figure><img src="https://www.techyrick.com/wp-content/uploads/2021/09/2021-09-26-19_38_54-Debian-10.x-64-bit-VMware-Workstation-16-Player-Non-commercial-use-only.webp" alt="nikto"><figcaption></figcaption></figure>

#### Example7:

Ignoring certain codes HTTP codes

<pre><code><strong>nikto -h example.com -no404
</strong></code></pre>

<figure><img src="https://www.techyrick.com/wp-content/uploads/2021/09/2021-09-26-19_43_28-Debian-10.x-64-bit-VMware-Workstation-16-Player-Non-commercial-use-only.webp" alt="nikto"><figcaption></figcaption></figure>

#### Example8:

Scanning multiple ports

<pre><code><strong>nikto -h example.com -port 44,80,22
</strong></code></pre>

<figure><img src="https://www.techyrick.com/wp-content/uploads/2021/09/2021-09-26-20_03_33-Debian-10.x-64-bit-VMware-Workstation-16-Player-Non-commercial-use-only.webp" alt="nikto"><figcaption></figcaption></figure>

### Conclusion:

Some alternatives for Nikto is Arachni, ZAP, searchsploit, Nessus, openVAS and I specifically love this nikto tool and just give it a try to this tool. Overall this is one of the best tools to scan for vulnerabilities and see you in the next post. 🍺
