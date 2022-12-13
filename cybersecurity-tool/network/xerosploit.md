# Xerosploit



* [Pre-requisites](broken-reference)
* [Overview on Xerosploit](broken-reference)
  * [Step-1: Installation](broken-reference)
  * [Step-2: Mapping the network/scanning the network](broken-reference)
  * [Step-3: Choosing the target device](broken-reference)
  * [Step-4: Performing port scan](broken-reference)
  * [Step-5: Inject HTML](broken-reference)
  * [Step-6: Inject Js](broken-reference)
  * [Step-7: Replace](broken-reference)
* [Conclusion](broken-reference)

Hello learners, we have learnt of how [man in the middle attacks](https://www.golinuxcloud.com/man-in-the-middle-attack-arp-spoofing/) can be performed previously. In this article we will be using xerosploit app to perform these attacks on the targeted devices within our network. A combination use of xerosploit tool and  [Airgeddon tool](https://www.golinuxcloud.com/wpa2-wifi-honeypot-tutorial/) which we did on our previous article, can be very resourceful when performing penetration testing on client devices. Some of these attacks which will be demonstrated in these guide can also be executed using other tools such as the [BEeF framework](https://www.golinuxcloud.com/beef-hacking-framework-tutorial/). man in the middle attacks are a powerful tool especially when used for phishing on the client for important information.

WARNING:

Before performing an penetration testing on any network and device, make sure you obtained consent since hacking without consent of the victims is punishable by law.

### Pre-requisites

1. Penetration Testing Linux Distro
2. Have a working WiFi card.
3. Basic Knowladge In Linux Command Line
4. Have a target device. (It should be connected to the same access point as you during the time of the attack).

### Overview on Xerosploit

Xerosploit is a tool used by penetration testers to perform man in the middle attacks for the purpose of testing. It utilizes features found within the nmap and bettercap to carry out the attacks. These features include, Denial of Service and port scanning. Some of the features found within xerosploit include;

Port scanning - Attackers can carryout port scanning on the target device within their network to exploit open and unsecured port found on the client device.

* **Network mapping** - using xerosploit, an attacker is able to map the target network and identify the devices that are on the network.
* **DoS attack** - Xerosploit can be used to launch a Denial of Service attack on a specific device within a network.
* **HTML code injection** -  HTML code injection can be used by attackers against in a device to lure the target client to disclose confidential information. i.e. Asking for confidential banking details.
* **JavaScript code injection** - Via advanced JavaScript code injection, an attacker can force the browser to perform actions mimicking the actions of a person. JavaScript codes can also be injected to allow the attacker to control the target device.
* **Download interception and replacement** - xerosploit allows the attacker to replace files being downloaded with malicious files on he client’s device.
* **Background audio reproduction** - Attackers can be able to play audio on the targets device via his/her browser.
* **Webpage defacement** - An attacker can deface a web page that is being visited by the client device.

### Step-1: Installation

To install xerosploit we will download the tool files from the [official GitHub repository](https://github.com/LionSec/xerosploit) using the command:

```
git clone https://github.com/LionSec/xerosploit
```

After downloading xerosploit tool we will navigate into its directory from and install r the tool to start using it.

```
cd xerosploit
```

```
sudo python install.py
```

After the installation is complete we can now run and start using the tool to perform man in the middle attacks

```
sudo python xerosploit.py
```

![xerosploit](https://www.golinuxcloud.com/wp-content/uploads/Picture1-1.jpg)

### Step-2: Mapping the network/scanning the network

As shown on the image above, we are on the “home page” of xerosploit tool. You can use command ‘help’  to check the commands list and their functions as shown on the image below

![xerosploit](https://www.golinuxcloud.com/wp-content/uploads/Picture2-15.jpg)

We will scan the network using command “**scan**”. Depending on the size of your network, it may take a few seconds or even minutes to complete the scan.

### Step-3: Choosing the target device

When scan is complete we are choose the target device on the network. You enter the target’s local IP address and press enter.

![xerosploit](https://www.golinuxcloud.com/wp-content/uploads/Picture3.jpg)

### Step-4: Performing port scan

After selecting the target device, our first attack is to scan the open ports on our target system. To scan this, we will use the pscan module using command “**pscan**”. This command will check for open ports on our target device as shown on the image below.

![xerosploit](https://www.golinuxcloud.com/wp-content/uploads/Picture4-16.jpg)

### Step-5: Inject HTML

This kind of attack is similar to the “inject Js” attack on xerosploit. However, in this attack, the attacker aims at adding HTML content to the webpage on an insecure website. To launch this attack we select to  use the inject HTML module and specify the path to our HTML file on the computer as shown on the image below.

![xerosploit](https://www.golinuxcloud.com/wp-content/uploads/Picture5.jpg)

When the attacker reloads the page we can see the injected HTML content at the top of the web page as shown on the image below.

### Step-6: Inject Js

Another attack which can be performed is injecting JavaScript code to a insecure website. Injecting JavaScript code can be used maliciously to ask for user’s personal details or perform other kinds of attacks. To run this kind of an attack is almost similar to replacing images, only that on this attack you specify the location of your JavaScript file instead.

![xerosploit](https://www.golinuxcloud.com/wp-content/uploads/Picture6.jpg)

We injected a JavaScript file with an alert to the user as shown on the image below.

![xerosploit](https://www.golinuxcloud.com/wp-content/uploads/Picture7-15.jpg)

### Step-7: Replace

The replace module replaces all the images found on the page of an insecure website which is being visited by the target device. To run this attack, we will use command replace on the modules menu. Xerosploit tool just needs us to specify the location of the image file that we want to replace with as shown on the image below.

![xerosploit](https://www.golinuxcloud.com/wp-content/uploads/Picture8-13.jpg)

As you can see on the image above, we will provide the location of the image want to use then we reload the insecure website and see that all the images were replaced with the image that we just specified above.

### Conclusion

On the above guide we were able to perform man in the middle attack on a target device on our network using xerosploit tool on Linux. This tool is a must have tool for pen-testers while performing penetration testing on networks. We were also able to illustrate how to use some of the modules on xerosploit to launch attacks related to them. There are other modules found on the tool that are resourceful to a pen-tester. Some of the modules include:

* dspoof — Redirect all the HTTP traffic to the specified one IP
* pscan — Port Scanner module
* deface — Overwrite all web pages with your HTML code
* dos — For Denial of Service attacks
* ping — To send oing requests to the target
* injecthtml — Injects HTML code while visiting insecure websites
* injectjs — Inject Javascript code while visiting insecure websites
* rdownload — Replace files being downloaded from insecure websites
* sniff — Captures information inside network packets
* yplay — Play background sound in target browser
* replace — Replace all web pages images with your own one
* driftnet — View all images requested by your targets
* move — Shakes Web Browser Content
