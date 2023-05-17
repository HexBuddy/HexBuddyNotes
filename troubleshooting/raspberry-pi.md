# Raspberry Pi

## So Today I Faced  A Problem In Connecting My Raspberry pi Into The HDMI Of My TV

## So I Used This Solution :&#x20;



## 1. First I Turned Off The Raspberry Pi And Removed The SD Card

## 2. Secondly I Got An "SD Adapter" And Plugged The SD Inside The Adapter&#x20;

### It Looks Something Like This :&#x20;

![](../.gitbook/assets/image.png)

## 3. Then I Plugged The Adapter Inside The Laptop To Read Filesystem On The SD Card

## 4.After The Filesystem Is Infront Of Me Now, I will Lookup For a File Named "config.txt"

## 5. Next I Opened The File With Notepad And Added These Lines Of Code : &#x20;

```
hdmi_force_hotplug=1
hdmi_group=1
hdmi_mode=76
disable_overscan=1
```

## Short Explanation For Each Line&#x20;

## hdmi\_force\_hotplug=1

<figure><img src="../.gitbook/assets/Screenshot 2023-05-17 025617.png" alt=""><figcaption></figcaption></figure>

## hdmi\_group=1

<figure><img src="../.gitbook/assets/InkedScreenshot 2023-05-17 025805.jpg" alt=""><figcaption></figcaption></figure>

## hdmi\_mode=76

<figure><img src="../.gitbook/assets/InkedScreenshot 2023-05-17 030351.jpg" alt=""><figcaption></figcaption></figure>

## disable\_overscan=1

<figure><img src="../.gitbook/assets/Screenshot 2023-05-17 030519.png" alt=""><figcaption></figcaption></figure>

##

## Last I Save The My Changed And Replug The SD Card Into The Raspberry Pi And Boot It Up

## Hope That Helped You !

## Happy Hacking !

<figure><img src="https://images.unsplash.com/photo-1587919057555-d728ff5beac3?crop=entropy&#x26;cs=srgb&#x26;fm=jpg&#x26;ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHw2fHxyYXNwYmVycnklMjBwaXxlbnwwfHx8fDE2ODQyNzgzNzF8MA&#x26;ixlib=rb-4.0.3&#x26;q=85" alt=""><figcaption></figcaption></figure>
