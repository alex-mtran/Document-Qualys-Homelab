# Qualys Vulnerability Management Homelab
This repository documents the Qualys vulnerability scanner appliance setup and usage including setting up virtual machine scanner appliance, configuring of scanner IP range, connecting host machine to scanner, creating scan profiles, reporting/ticketing vulnerabilities, understanding/remediating vulnerabilities, and verification of remediations.

Of the Qualys Vulnerability Management Lifecycle phase, this documentation will cover phases 3 through 6 (Assess, Report, Remediate, Verify). Phase 1 and 2 (Discovery, Asset Organization) are for bigger networks of devices and information forwarding. As this homelab contains just the scanner appliance and the one machine to be scanned, there is no need for discovering all devices or for asset organization.

<img width="618" height="420" alt="image" src="https://github.com/user-attachments/assets/684c8c83-6ef4-44e5-a873-54990ab31671" />

### Virtual Scanner Appliance vs Cloud Agent

Qualys offers two primary approaches for vulnerability management: the **Virtual Scanner Appliance** and **Cloud Agent**. In an ideal, comprehensive homelab environment, both would be deployed as they provide distinct yet complementary scanning capabilities.

For this homelab, I chose to implement **only the Virtual Scanner Appliance** for the following reasons:

- **Static environment**: My homelab consists of on-premise assets with controlled, predictable configurations
- **Sufficient coverage**: Network-based scanning adequately covers my use case for point-in-time vulnerability assessments
- **Acceptable scan frequency**: Weekly scheduled scans meet my security monitoring needs
- **Tolerable performance impact**: I can accommodate network performance degradation during deep scans

**This approach is NOT recommended for production or enterprise environments.**

**Gaps with scanner-only deployment:**
- **No real-time visibility**: Vulnerabilities discovered only during scheduled scans
- **Coverage blind spots**: Roaming laptops, remote workers, and non-persistent VMs (VDI) may be missed between scans
- **Limited accuracy**: External scanning lacks the depth and context of authenticated, agent-based assessments
- **Network performance**: Deep scans can impact production networks—acceptable in a homelab but problematic at scale

In enterprise scenarios, **both scanner appliances and cloud agents should be deployed** to ensure comprehensive coverage, continuous monitoring, and minimal operational impact.

#### Key Differences

**Virtual Scanner Appliance**
- Network-based scanning solution that scans entire networks from the perimeter
- Capable of discovering and assessing devices that cannot install agents (e.g., IoT devices, network equipment)
- Detects remote-only vulnerabilities and performs unauthenticated scans
- Operates on a scheduled scan basis (weekly, daily, etc.)

**Cloud Agent**
- Lightweight agent installed directly on endpoints
- Provides continuous, real-time authenticated scanning
- Ideal for dynamic, remote, or cloud-based assets
- Offers deeper visibility into system configurations and installed software

---

## Table of Contents 
1. [Initial Setup](#initial-setup-anchor-point)
2. [Setting Configurations](#setting-configurations-anchor-point)
3. [Scanning and Scan Profiles](#scanning-and-scan-profiles-anchor-point)
4. [Logs and Remediation](#logs-and-remediation-anchor-point)
5. [Challenges Solutions](#challenges-solutions-anchor-point)

---

<a name="initial-setup-anchor-point"></a>
## Initial Setup

**Agent(s):** Windows 11 Home (host machine) <br>
**VM Manager:** Oracle VirtualBox <br>
**Qualys edition:** Community Edition <br>

Qualys is a popular tool for scanning vulnerabilities and for performing threat assessments on connected endpoints. For the initial setup, we will need a virtual machine manager (I will be using <a href="https://www.virtualbox.org/" target="_blank" rel="noopener noreferrer">Oracle VirtualBox</a>) to host the scanner appliance and to establish a connection from the scanner to the machine(s) of choice (in this documentation, just the one Windows 11 machine). 

We will start from the Qualys homepage right after creating and signing into an account. <a href="https://www.qualys.com/community-edition" target="_blank" rel="noopener noreferrer">Qualys Community Edition</a>.

#### Download virtual scanner

<img width="735" height="657" alt="image" src="https://github.com/user-attachments/assets/b8a85288-4ae1-4d73-a64f-45b036fc159b" />

#### Start wizard

<img width="344" height="161" alt="image" src="https://github.com/user-attachments/assets/028b6db3-8bbd-4ef6-92d6-48f7ee506af3" />

Fill in:
- TestVA
- VMWare ESXi, vCenter Server (standard)


<img width="364" height="137" alt="image" src="https://github.com/user-attachments/assets/6dcebe06-a3a0-4842-9bde-7372a3386e05" />

Hit next a couple times. They will provide a personalization code to input into the virtual machine, keep note of this personalization code. Next, we will configure the appliance in Oracle VirtualBox.

--- 

### Oracle VirtualBox

1. Start up the Oracle VirtualBox app
2. File > Import Appliance...
3. Select the downloaded `.ova` file

> **Note:** This is the homepage of the Oracle VM VirtualBox Manager. Ignoring that I already have a couple VMs created including the Qualys scanner, here's how to set it up for the first time.

<img width="304" height="338" alt="image" src="https://github.com/user-attachments/assets/7963cd4e-f849-491d-b30b-96d4eb4ad4fd" />

Click the folder icon and navigate to downloaded `.ova` file. Finish the import.

<img width="921" height="599" alt="image" src="https://github.com/user-attachments/assets/ce9592d2-5b26-4ea4-a323-4d0592c53783" />

<br>Navigate to where the downloaded OVA file is and press it.

Start the scanner VM by double-clicking it or selecting it and pressing **Start**.

<img width="414" height="176" alt="image" src="https://github.com/user-attachments/assets/033329b5-55fe-4a0c-bf95-f858ddbd6a04" />

Enter **personalization code** obtained earlier.

> **Note:** To view mouse once in the scanner VM, press right CTRL.

<img width="382" height="317" alt="image" src="https://github.com/user-attachments/assets/b4116224-daa7-4662-88ce-2fc72760dadc" />

Wait for the scanner to connect with the Qualys Cloud. Then, in the Qualys web console, check:

**Scans > Appliances**  

Virtual appliance should now be listed.

---

<a name="setting-configurations-anchor-point"></a>
## Setting Configurations

Set up the IP range the scanner is allowed to scan. The Qualys Community Edition restricts scans to **19 devices**.

**Scans > New > IP Tracked Addresses > Subscription IPs**

Input desired IP range (e.g., `192.168.0.2-192.168.0.18`) and press **Add**.

<img width="627" height="174" alt="image" src="https://github.com/user-attachments/assets/3894302e-364d-4756-9e87-18b9ccd8b8a6" />


> **Note:** For this lab, the Host-Only adapter IP `192.168.57.1` is used in a **dual-adapter setup**: NAT + Host-Only. Adapter 1 must be NAT for proper DNS and cloud connectivity.

To view your IP address on Windows:

- Type `cmd` into the Search bar of the Windows taskbar and press `Enter`
- Type in `ipconfig` into the shell to view all network adapters. Use the **Host-Only adapter** for scanning. The NAT/internet-facing adapter is for uploading results

```bash
Ethernet adapter Ethernet 3:

   .....
   IPv4 Address. . . . . . . . . . . : 192.168.57.1
   .....
```

To simplify the process of assigning the Host-Only adapter, statically assign the IP address and reserve its address in the router's DHCP.

#### How to set static private IP address (Windows):
1. Open **Control Panel** > Network and Internet > Network and Sharing Center > Change adapter settings
2. Right-click the host-only adapter > Properties
3. Select **Internet Protocol Version 4 (TCP/IPv4)** > Properties > Use the following IP address:
   * IP Address: Desired IP that is not currently in use
   * Subnet mask: Corresponding subnet
   * Default gateway: leave blank (host-only)
4. Press **OK**

<img width="722" height="363" alt="image" src="https://github.com/user-attachments/assets/ad7a5f0f-0b58-4835-a2be-03e17791cec2" />

To verify the IP is available, check your router's DHCP reservations or active clients.

---

<a name="scanning-and-scan-profiles-anchor-point"></a>
## Scanning and Scan Profiles

In the Qualys homepage navigate to:

**Scans > Option Profiles > New > Option Profile...**

<img width="670" height="573" alt="image" src="https://github.com/user-attachments/assets/34dae88b-6354-49ac-b2b1-8d9de502ca5d" />

Fill in:
* Name: Basic Net Scan
* Leave settings as default > Save

<img width="714" height="851" alt="image" src="https://github.com/user-attachments/assets/7a9755e0-0d1e-4446-8224-ab23cb17ed32" />

**Unauthenticated scan:** scans externally-facing ports/services <br>
**Authenticated scan:** uses credentials for a deeper assessment

### Unauthenticated Scan
**Scans > New > Scan**

<img width="677" height="176" alt="image" src="https://github.com/user-attachments/assets/6c065754-cdd6-4c02-95a6-e8250c5ca5e3" />

* Title: Win11 Unauth Scan Host-Only
* Option Profile: Basic Net Scan
* Scanner Appliance: TestVA
* IPv4 Addresses/Ranges: 192.168.57.1 (host-only adapter)
* Launch

> **Note:** Make sure Qualys Virtual Scanner Appliance is on and running in the background.

### Authenticated Scan

Settings needed:
* Enable and start `Remote Registry` (Services > `Remote Registry` > Right-click > Properties > Startup Type: Automatic > Apply > OK > Right-click > Start).
  * This will enable remote users to modify registry settings. This allows Qualys as a remote system to query installed software, patch levels, OS configuration, and security policies. Without it, Qualys would have many checks fall to the "potentially vulnerable" state
* Enable and start `Server` (Services > `Server` > Right-click > Properties > Startup Type: Automatic > Apply > Right-click > Start)
  * Allows remote systems to connect over ports 139 and 445 (NetBIOS and TCP/IP). This allows Qualys to authenticate with Windows credentials and to enumerate files, services, and permissions
* Enable **File and Printer Sharing** for the network profile (Manage advanced sharing settings > Turn on **File and Printer Sharing)
    * Allows inbound file-sharing connections. This allows Qualys to bypass the firewall to reach SMB services
* Disable UAC prompts (Change User Account Control settings > Never notify > OK)
  * Reduces privilege separation for local admin accounts. This allows Qualys to access admin credentials fully, remotely, without checks failing or returning incomplete data from downgraded admin tokens
* Disable remote UAC filtering for local admins (Registry Editor > Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System > New DWORD (32-Bit) Value > `LocalAccountTokenFilterPolicy` = 1)
  * Local admins get full admin rights remotely. This allows Qualys to do authenticated scans properly without checks silently failing or _appearing_ to succeed

> **Note:** These settings should be **temporary** and reverted after scanning. While there is no real risk as only machines on the 192.168.57.0/24 range can connect during the scan (and there are no other machines on the 192.168.57.0/24 range), leaving these settings enabled weakens protections and creates a bigger attack vector. Thus, we must revert these settings after authenticated scanning. These practices align with industry standard of only temporarily enabling these settings/managing them via group policy/using domain credentials.

#### Configure Authenticated Scan in Qualys

**Scans > Authentication > New > Operating Systems... > Windows**

<img width="771" height="675" alt="image" src="https://github.com/user-attachments/assets/1162a1e7-0d23-4cb8-9017-c5c86f1d0b01" />

Fill in:

* Record Title > Title: Win11 Credentials
* Login Credentials > Windows Authentication : Enable Local
* Login Credentials > Login : Basic authentication : username/password
* Login Credentials > Login : NTLMv1 and NTLMv2 protocol enabled
* IP(s): 192.168.57.1
* Save

**Option Profiles > Basic Net Scan > Down Arrow > Edit > Enable Windows authentication > Save**

<img width="961" height="242" alt="image" src="https://github.com/user-attachments/assets/833aeec0-3dd0-460d-a339-72fd6bca9eca" />

> **Note:** Here, we are editing our previous Basic Net Scan instead of creating a new scan profile because the Qualys Community Edition only allows for 1 option profile. 

Launch the authenticated scan like the unauthenticated one, changing the title and keeping the same appliance/IP.

#### <ins>**Unauthenticated Scan Results:**</ins>

<img width="995" height="621" alt="image" src="https://github.com/user-attachments/assets/28e03a4d-6a7d-413c-8460-8f346512e1af" />

<img width="995" height="679" alt="image" src="https://github.com/user-attachments/assets/1b38da49-ba8f-48f1-86e4-d6a8554ef82c" />

#### <ins>**Authenticated Scan Results:**</ins>

<img width="996" height="618" alt="image" src="https://github.com/user-attachments/assets/9ff485a3-7dea-40bb-9859-3f4397c54bed" />

<img width="996" height="528" alt="image" src="https://github.com/user-attachments/assets/65555575-a85a-4f0e-b26c-bbe06aab1ac5" />

While authenticated scans are not strictly required every time, they are **highly recommended for regular vulnerability management** due to their comprehensive and accurate results. 

**A balanced strategy combines:**
- **Authenticated scans** as the primary method for detailed, ongoing assessment
- **Unauthenticated scans** periodically to simulate an external attacker's view and validate exposure

This dual approach ensures both internal security hygiene and external attack surface visibility.

---

<a name="logs-and-remediation-anchor-point"></a>
## Logs and Remediation

#### Severity Levels and Types:

<img width="994" height="660" alt="image" src="https://github.com/user-attachments/assets/0655aa93-915c-4766-82d9-542d5139a703" />

### Vulnerability Patch Prioritization

When prioritizing vulnerabilities for remediation, follow this strategy:

1. **Severity first**: Address vulnerabilities by risk level, starting with Critical and High severity findings
2. **Age second**: For vulnerabilities of the same severity, prioritize older detections (first discovered date)

This approach maximizes remediation value by:
- Mitigating the highest-impact threats first
- Reducing exposure time for equally severe vulnerabilities (older findings have been exploitable longer, increasing likelihood of compromise)

#### Example vulnerability:

<img width="995" height="543" alt="image" src="https://github.com/user-attachments/assets/b046a894-15d8-4231-ac92-387384242b83" />

**Key fields to review:**

- **QID (Qualys ID)**: Unique identifier for the vulnerability (e.g., `82005`)
- **Title**: Descriptive name of the vulnerability (e.g., "Predictable TCP Initial Sequence Numbers Vulnerability")
- **Severity**: Risk level and vulnerability type (indicated by number and color coding respectively)
- **Category**: Vulnerability classification (e.g., `TCP/IP`)
- **CVE IDs**: Industry-standard Common Vulnerabilities and Exposures identifiers for cross-referencing

**Understanding the risk:**

1. **THREAT**: Explains what the vulnerability is and how it can be exploited
2. **IMPACT**: Describes the potential consequences if exploited (e.g., session hijacking, spoofing, connection disruption)
3. **EXPLOITABILITY**: Links to proof-of-concept exploits or references from Exploit-DB, indicating active exploitation risk

**Steps to patch/remediate:**

1. **SOLUTION**: Provides specific remediation guidance
   - May include OS updates, configuration changes, or vendor patches
   - Often contains direct links to vendor advisories or patches

2. **Check Vendor References**: Follow links to official vendor documentation
   - Microsoft Security Bulletins (MS##-###)
   - Cisco advisories
   - CVE databases for additional context

3. **Apply appropriate fixes**:
   - **OS-level patches**: Update systems through vendor patch management
   - **Configuration changes**: Modify settings as specified (e.g., TCP/IP stack hardening)
   - **Workarounds**: Implement temporary mitigations if patches are unavailable

**After applying remediation:**

1. **Re-scan the affected asset**: Run a targeted or full scan on the remediated system
2. **Verify QID removal**: Confirm the specific QID no longer appears in scan results
3. **Check "Service Modified" date**: Updated scan results should reflect recent changes
4. **Review "PCI Vuln" status**: If applicable, ensure compliance requirements are met
5. **Report remediation and patch**: Write a report in your change management system with QID reference and scan dates

---

<a name="challenges-solutions-anchor-point"></a>
## Challenges Solutions

A mismatch between the Qualys scanner’s network configuration and VirtualBox adapters caused DNS failures. Initially, the scanner was assigned a host-only IP (`192.168.57.0/24`) while attached only to NAT. Because the scanner was manually configured with an IP address, gateway, and DNS settings from the Host-Only network—while no Host-Only adapter was present—the scanner attempted to use a non-existent gateway. This prevented cloud connectivity and triggered LAN DNS errors.

<a href="https://www.youtube.com/watch?v=Fhdxk4bmJCs" target="_blank" rel="noopener noreferrer">For more information on the different network adapter settings in VirtualBox</a>

### Resolution
* Revert scanner to DHCP
* Configure **dual adapters**: NAT (for cloud connectivity) + Host-Only (for local scans)

> **Note:** This dual-homed configuration aligns with common industry practices by separating management and cloud communication traffic from internal scanning traffic, restoring full scanner functionality in both scenarios.

Manual remediation and authenticated scan verification were time-consuming, leading to PowerShell automation scripts: <a href="https://github.com/alex-mtran/windows-authenticated-scan-setup"  target="_blank" rel="noopener noreferrer">Windows Authenticated Scan Setup</a>).

Future expansion:
* Add more devices (IoT, network infrastructure, different operating systems, etc.)
  * Sort inventory using asset tags
* Integrate Active Directory for group policy management
* Configure authenticated scans and automated patching via VMDR and Patch Management
