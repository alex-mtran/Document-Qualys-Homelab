# Qualys Vulnerability Management Homelab
This repository documents the Qualys vulnerability scanner appliance setup and usage including setting up virtual machine scanner appliance, configuring of scanner IP range, connecting host machine to scanner, creating scan profiles, reporting/ticketing vulnerabilities, understanding/remediating vulnerabilities, and verification of remediations.

Of the Qualys Vulnerability Management Lifecycle phase, this documentation will cover phases 3 through 6 (Assess, Report, Remediate, Verify). Phase 1 and 2 (Discovery, Asset Organization) are for bigger networks of devices and information forwarding. As this homelab contains just the scanner appliance and the one machine to be scanned, there is no need for discovering all devices or for asset organization.<br>
<img width="618" height="420" alt="image" src="https://github.com/user-attachments/assets/684c8c83-6ef4-44e5-a873-54990ab31671" />

<br><br><br><br><br>




## Table of Contents 
1. [Initial Setup](#initial-setup-anchor-point)
2. [Setting Configurations](#setting-configurations-anchor-point)
3. [Scanning and Scan Profiles](#scanning-and-scan-profiles-anchor-point)
4. [Logs and Remediation](#logs-and-remediation-anchor-point)
5. [Problems Issues Conclusion](#problems-issues-conclusion-anchor-point)
<br><br><br><br><br>










<a name="initial-setup-anchor-point"></a>
## Initial Setup

Agent(s): Windows 11 Home (host machine)<br>
VM Manager: Oracle VirtualBox<br>
Qualys edition: Community Edition<br>

Qualys is a popular tool for scanning vulnerabilities and for performing threat assessments on connected endpoints. For the initial setup, we will need a virtual machine manager (I will be using <a href="https://www.virtualbox.org/" target="_blank" rel="noopener noreferrer">Oracle VirtualBox</a>) to host the scanner appliance and to establish a connection from the scanner to the machine(s) of choice (in this documentation, just the one Windows 11 machine). 

We will start from the Qualys homepage right after creating and signing into an account. <a href="https://www.qualys.com/community-edition" target="_blank" rel="noopener noreferrer">Qualys Community Edition</a>.

<br>Download virtual scanner

<img width="735" height="657" alt="image" src="https://github.com/user-attachments/assets/b8a85288-4ae1-4d73-a64f-45b036fc159b" />

<br>Start wizard

<img width="344" height="161" alt="image" src="https://github.com/user-attachments/assets/028b6db3-8bbd-4ef6-92d6-48f7ee506af3" />

<br>Fill out information:<br>
(any virtual scanner name you would like, i.e. TestVA)<br>
VMWare ESXi, vCenter Server (standard)


<img width="364" height="137" alt="image" src="https://github.com/user-attachments/assets/6dcebe06-a3a0-4842-9bde-7372a3386e05" />

<br>Hit next a couple times. They will provide a personalization code to input into the virtual machine, keep note of this personalization code. Next, we will configure the appliance in Oracle VirtualBox.
<br><br><br>
#### Oracle VirtualBox

Start up the Oracle VirtualBox app.<br>
Press File > Import Appliance...<br>
NOTE: This is the homepage of the Oracle VM VirtualBox Manager. Ignoring that I already have a couple VMs created including the Qualys scanner, here's how to set it up for the first time.<br>
<img width="304" height="338" alt="image" src="https://github.com/user-attachments/assets/7963cd4e-f849-491d-b30b-96d4eb4ad4fd" />

<br>Press the folder icon
<img width="921" height="599" alt="image" src="https://github.com/user-attachments/assets/ce9592d2-5b26-4ea4-a323-4d0592c53783" />

<br>Navigate to where the downloaded OVA file is and press it.

After finishing installation, double click the scanner or highlight the scanner VM and then press Start to open it.

<img width="414" height="176" alt="image" src="https://github.com/user-attachments/assets/033329b5-55fe-4a0c-bf95-f858ddbd6a04" />

<br>Enter personalization code obtained previously.<br>
NOTE: To view mouse once in the scanner VM, press right CTRL.

<img width="382" height="317" alt="image" src="https://github.com/user-attachments/assets/b4116224-daa7-4662-88ce-2fc72760dadc" />

<br>Wait for the scanner to connect with the Qualys cloud profile and then view the browser Qualys page once more.

The appliance should now be listed, check under Scans (in the left panel) > Appliances (top center bar) and check to see that there is the virtual appliance.
<br><br><br><br><br>










<a name="setting-configurations-anchor-point"></a>
## Setting Configurations

This next section is to set up the IP range for the scanner. On the community free version of Qualys, there will be a restriction of only being able to scan 19 devices.

Press Scans (in the left panel)

Press New > IP Tracked Addresses > Subscription IPs

<img width="260" height="151" alt="image" src="https://github.com/user-attachments/assets/aa81d292-c778-4bf5-82b2-87880ef29b29" />

Input IP range of devices you'd like to scan (i.e., 192.168.0.200,192.168.0.2-192.168.0.18). Press Add.<br>

<img width="924" height="211" alt="image" src="https://github.com/user-attachments/assets/dd3486db-1086-4818-b06d-cc92ab5bd505" />

NOTE: This is an image of my initial scan for a Win10 VM in which I used a bridged network adapter to have the VM as its own IP address on my home network. For the purposes of this documentation, my IP range is instead just the 192.168.57.1 IP address and the appliance is on a dual-adapter setup of NAT and Host-Only. This dual-adapter setup is in that particular order, too, as VirtualBox prioritizes Adapter1 over Adapter2, and having Host-Only as Adapter1 may lead to issues of the scanner sending DNS or cloud traffic over the Host-Only network which will lead to DNS or connectivity errors.

To view IP address of device (on Windows), type `cmd` into the Search bar of the Windows taskbar and press `Enter`. Then, in the shell type in `ipconfig` to view all network adapters. The desired adapter will scan the host-only adapter, not the internet-facing adapter (in my case: Ethernet adapter, not the Wireless LAN adapter). The internet-facing adapter will instead be used as the IP in which Qualys will upload the scan results over (via NAT inside the VM).

```bash
Ethernet adapter Ethernet 3:

   .....
   IPv4 Address. . . . . . . . . . . : 192.168.57.1
   .....

Wireless LAN adapter Wi-Fi 3:

   .....
   IPv4 Address. . . . . . . . . . . : *********
   .....
```

Furthermore, to simplify the process of assigning the host-only adapter, I opted to statically assign my host machine's IP address and reserve its address in my router's DHCP.

<ins>How to set a static private IP address on Windows 11:</ins>
* In Windows taskbar search bar, type and enter in `Control Panel`
  * Network and Internet > Network and Sharing Center > Change adapter settings
  * Right-click host-only adapter > Press Properties
    * Scroll down the This connection uses the following items: list and highlight Internet Protocol Version 4 (TCP/IPv4) by left-clicking it
    * Properties > Use the following IP address > Input desired IP address into the IP address field (make sure to input an IP that is not in use) and input Subnet mask relative to the set IP address of the host-only adapter > OK (leave default gateway blank, as this is a **host-only** adapter)

<img width="722" height="363" alt="image" src="https://github.com/user-attachments/assets/ad7a5f0f-0b58-4835-a2be-03e17791cec2" />

To check for a valid private IP address that is not being used on your network, sign into your router admin page and manually verify if the desired IP address is already in use.

<br><br><br><br><br>









<a name="scanning-and-scan-profiles-anchor-point"></a>
## Scanning and Scan Profiles

In the Qualys homepage go to:

Scans > Option Profiles > New > Option Profile...

<img width="670" height="573" alt="image" src="https://github.com/user-attachments/assets/34dae88b-6354-49ac-b2b1-8d9de502ca5d" />

Name the scan (i.e., Basic Net Scan) > Press scan > (Can adjust scan settings for different things but for now we'll leave them all as default) > Scroll down > Click save

The scan profile will now be listed.

<img width="714" height="851" alt="image" src="https://github.com/user-attachments/assets/7a9755e0-0d1e-4446-8224-ab23cb17ed32" />

What we have just created was a scan profile for an unauthenticated scan. As we will soon see, the Qualys recommended option profile (default) scan is pretty much exactly this scan, so we will later change our basic net scan.

Unauthenticated scan - Scans anything externally-facing (i.e., ports)<br>
Authenticated scan - Scans that are provided credentials to go into the machines to perform deeper scans

Scans > New > Scan

<img width="677" height="176" alt="image" src="https://github.com/user-attachments/assets/6c065754-cdd6-4c02-95a6-e8250c5ca5e3" />

Title: Name this specific instance of scan (i.e., Win11 Unauth Scan host-only)<br>
Option Profile: Select the previously created scan profile (Basic Net Scan)<br>
Scanner Appliance: Select the previously created appliance name (TestVA)<br>
IPv4 Addresses/Ranges: IP address we set up for the host-only adapter (192.168.50.194)<br>
Launch

Wait patiently as the scan takes awhile in queue and during scan to actually go through.<br>
NOTE: Make sure Qualys Virtual Scanner Appliance is on and running in the background.

To enable an accurate authenticated scan, we have to change a couple settings within the host machine. Below is the how-to's and explanations behind changing these settings via the GUI:
NOTE: For powershell scripts on running these cmdlets, see here: <a>Enabling Authenticated Scan Settings</a> | <a>Disabling Authenticated Scan Settings</a>

* Enable and run `Remote Registry` automatically
  * Services > `Remote Registry` > Right-click > Properties > Startup Type: Automatic > Apply > OK > Right-click > Start
  * This will enable remote users to modify registry settings. This allows Qualys as a remote system to query installed software, patch levels, OS configuration, and security policies. Without it, Qualys would have many checks fall to the "potentially vulnerable" state.
* Enable and run `Server` automatically
  * Services > `Server` > Right-click > Properties > Startup Type: Automatic > Apply > Right-click > Start
  * Allows remote systems to connect over ports 139 and 445 (NetBIOS and TCP/IP). This allows Qualys to authenticate with Windows credentials and to enumerate files, services, and permissions.
* Enable file and printer sharing
  * Manage advanced sharing settings > Turn on file and printer sharing
    * Turn on file and printer sharing for the specific network profile that you are on. For example, my home network is under the private profile so I only would turn it on for the private network profile
    * Allows inbound file-sharing connections. This allows Qualys to bypass the Firewall to reach SMB services.
* Disable UAC prompts
  * Change User Account Control settings > Never notify > OK
  * Reduces privilege separation for local admin accounts. This allows Qualys to access admin credentials fully, remotely, without checks failing or returning incomplete data from downgraded admin tokens.
* Disable remote UAC filtering for local admins
  * Registry Editor > Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System > New DWORD (32-Bit) Value : Value name=LocalAccountTokenFilterPolicy, Value data=1
  * Local admins get full admin rights remotely. This allows Qualys to do authenticated scans properly without checks silently failing or _appearing_ to succeed.

NOTE: The settings required for authenticated scanning are to be enabled only temporarily and reverted back to default after testing to restore the system’s security posture. Network isolation via a Host-Only adapter is further used to mitigate risk during the scan window. While there is no real risk as only VMs on 192.168.57.0/24 can talk to the machine during the scan, leaving these settings enabled weakens protections and creates a bigger attack vector. Thus, we must revert these settings after authenticated scanning. These practices align with industry standard of only temporarily enabling these settings/managing them via group policy/using domain credentials.

Now to create the authenticated scan go back to Qualys and follow the instructions below:

Scans > Authentication > New > Operating Systems... > Windows

<img width="771" height="675" alt="image" src="https://github.com/user-attachments/assets/1162a1e7-0d23-4cb8-9017-c5c86f1d0b01" />

Fill out New Windows Record (anything not stated can be left as default):

Record Title > Title: AnyTitle (ex: Win11 Credentials)
Login Credentials > Windows Authentication : Enable Local
Login Credentials > Login : Basic authentication : User Name=machineusername, Password=machinepassword, Confirm Password=machinepassword
Login Credentials > Login > Enable NTLMv1 and NTLMv2 protocol
IPs > Enter IP(s) of the machine we are performing the scan on (192.168.57.1)
Save

Option Profiles > Basic Net Scan > Down Arrow > Edit > Enable Windows authentication > Save<br>
<img width="961" height="242" alt="image" src="https://github.com/user-attachments/assets/833aeec0-3dd0-460d-a339-72fd6bca9eca" />

NOTE: Here, we are editing our previous Basic Net Scan instead of creating a new scan profile because the Qualys Community Edition only allows for 1 option profile. 

Now, same as with the unauthenticated scan we must configure and start a new scan.

Scans > New > Scan

<img width="677" height="176" alt="image" src="https://github.com/user-attachments/assets/6c065754-cdd6-4c02-95a6-e8250c5ca5e3" />

Title: Name this specific instance of scan (i.e., Win11 Auth Scan host-only)<br>
Option Profile: Select the previously created scan profile (Basic Net Scan)<br>
Scanner Appliance: Select the previously created appliance name (TestVA)<br>
IPv4 Addresses/Ranges: IP address we set up for the host-only adapter (192.168.50.194)<br>
Launch

<ins>**WINDOWS 11 UNAUTHENTICATED SCAN:**</ins>

<img width="995" height="621" alt="image" src="https://github.com/user-attachments/assets/28e03a4d-6a7d-413c-8460-8f346512e1af" />

<img width="995" height="679" alt="image" src="https://github.com/user-attachments/assets/1b38da49-ba8f-48f1-86e4-d6a8554ef82c" />
<br><br><br>
<ins>**WINDOWS 11 AUTHENTICATED SCAN:**</ins>

<img width="996" height="618" alt="image" src="https://github.com/user-attachments/assets/9ff485a3-7dea-40bb-9859-3f4397c54bed" />

<img width="996" height="528" alt="image" src="https://github.com/user-attachments/assets/65555575-a85a-4f0e-b26c-bbe06aab1ac5" />

<br><br><br><br><br>










<a name="logs-and-remediation-anchor-point"></a>
## Logs and Remediation

The severity levels and types are described here:<br>
<img width="994" height="660" alt="image" src="https://github.com/user-attachments/assets/0655aa93-915c-4766-82d9-542d5139a703" />

There are a lot of vulnerabilities to remediate on my host machine. I will analyze and remediate through two of these logs as an example of the thought process I use to patch up my machine.
<img width="995" height="543" alt="image" src="https://github.com/user-attachments/assets/b046a894-15d8-4231-ac92-387384242b83" />

TALK ABOUT HOW TO ANALYZE THE VULNERABILITY, CVEs, SOLUTION

<img width="997" height="553" alt="image" src="https://github.com/user-attachments/assets/d4592483-a577-4e05-a2cb-cc33b87182dc" />

HERE TOO AHHHHHHHHHHHHH

<br><br><br><br><br>










<a name="problems-issues-conclusion-anchor-point"></a>
## Problems Issues Conclusion

There was an issue involving mismatched network adapter settings and the internal configuration of the Qualys scanner. I initially set a static IP in the 192.168.57.0/24 range, which is used for a Host-Only network, while the scanner’s adapter was actually set to NAT. NAT assigns IPs in the 10.0.2.0/24 range. Thus the scanner was pointing to a gateway that didn’t exist, preventing DNS traffic from leaving the VM and causing a LAN DNS error. The fix was to switch the scanner to DHCP and to have a dual-adapter setup (NAT and Host-Only), allowing NAT to assign the correct 10.0.2.x address and restore connectivity. The dual-adapter setup also aligns more closely with the industry standard by providing cloud communication, DNS resolution, updates, etc., while also isolating the host machine local scans. My particular Qualys scanner IP range is then set to just the Host-Only 192.168.57.1 address and only uses NAT for management. This setup resolves the DNS issue and allows the scanner to function for both scenarios (which is not correct, but is much more convenient and safe enough in my homelab scenario).

Resolving the vulnerabilities also took awhile, particularly with the verification process involving rescanning the target machine. The overhead of manually reconfiguring the authenticated scan settings proved too taxing and I learned to create basic PowerShell scripts to automate this process much more efficiently. 

Moving forward with this vulnerability management homelab, I would like to expand my management network via adding more devices and looking towards Active Directory in order to handle group policies. As for the vulnerability patches themselves, I would like to configure authenticated scans to identify vulnerabilities, define asset tags, and create automated patch jobs using VMDR and Patch Management to target vulnerabilities.

<a href="https://www.youtube.com/watch?v=Fhdxk4bmJCs" target="_blank" rel="noopener noreferrer">For more information on the different network adapter settings in VirtualBox</a>

