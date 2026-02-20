# Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM

## Project Overview

This project simulates a real-world enterprise Active Directory environment to demonstrate attack detection and log analysis using Splunk SIEM. A multi-VM lab was built consisting of a Domain Controller (Windows Server 2022), a domain-joined Windows 10 client, a Splunk server (Ubuntu), and an attacker machine (Kali Linux).

The lab focuses on detecting authentication-based attacks and adversary techniques. A brute-force attack was conducted using Hydra to compromise domain user accounts, generating Windows Security Event IDs 4625 (failed logon) and 4624 (successful logon), which were analyzed in Splunk.

Additionally, Atomic Red Team was used to simulate MITRE ATT&CK techniques such as PowerShell execution (T1059.001), allowing further validation of detection visibility through Sysmon and Windows Event Logs.

This project demonstrates hands-on experience in Active Directory administration, SIEM log ingestion, attack simulation, and SOC-level security analysis.

## 🏗️ Lab Architecture
### 🔹 Architecture Diagram

![Lab Architecture](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/Active_Directory.drawio.png)

This lab environment was designed to simulate a small enterprise network with centralized log monitoring and attack detection capabilities.

### 🔹 Virtual Machines Used

- **Windows Server 2022**
  - Configured as Domain Controller
  - Active Directory Domain: `games.local`
  - User account management and authentication

- **Windows 10**
  - Domain-joined client machine
  - Generates authentication and system logs
  - Target of brute-force and MITRE ATT&CK simulations

- **Ubuntu Server**
  - Hosted Splunk Enterprise
  - Centralized log collection and analysis

- **Kali Linux**
  - Attacker machine
  - Used Hydra for brute-force simulation
  - Used for offensive testing against domain users

---

### 🔹 Log Flow Architecture

1. Windows Server and Windows 10 generate Security and Sysmon logs.
2. Splunk Universal Forwarder installed on both Windows machines forwards logs to the Splunk server (Ubuntu).
3. Splunk indexes and stores the logs.
4. Log analysis and detection queries are performed within Splunk.
5. Attack simulations from Kali Linux generate authentication and execution events that are captured and analyzed.

---
## 🛠️ Technologies Used

### 🔹 Operating Systems
- Windows Server 2022 (Active Directory Domain Controller)
- Windows 10 (Domain Client)
- Ubuntu Server (Splunk SIEM)
- Kali Linux (Attacker Machine)

### 🔹 SIEM & Log Management
- Splunk Enterprise
- Splunk Universal Forwarder
- Windows Event Logs
- Sysmon (System Monitor)

### 🔹 Attack & Simulation Tools
- Hydra (Brute-force attack simulation)
- Atomic Red Team
- MITRE ATT&CK Framework

### 🔹 Networking & Virtualization
- VirtualBox
- Internal Lab Network Configuration

### 🔹 Security Concepts Applied
- Active Directory Authentication
- Log Ingestion & Indexing
- Event ID Analysis (4624, 4625)
- Brute Force Detection
- MITRE ATT&CK Technique Simulation
- SOC Investigation Workflow

## 🧪 Lab Environment Setup

The lab was built using a multi-VM architecture to simulate an enterprise domain environment with centralized log monitoring.

### 🔹 Virtual Machine Configuration

Four virtual machines were deployed using VirtualBox:

| Machine | Role | Purpose |
|----------|--------|-----------|
| Windows Server 2022 | Domain Controller | Active Directory, authentication services |
| Windows 10 | Domain Client | Generates user authentication and endpoint logs |
| Ubuntu Server | SIEM Server | Hosts Splunk Enterprise |
| Kali Linux | Attacker Machine | Performs brute-force and adversary simulations |

---

### 🔹 Network Configuration

- All machines were connected to the same internal lab network.
- Static IP addresses were configured to ensure consistent communication.
- Connectivity between machines was verified using `ping`.
- Proper DNS configuration was applied to allow domain resolution (`games.local`).

---

### 🔹 Verification Steps

- Confirmed all VMs could communicate over the internal network.
- Verified Windows 10 could resolve and reach the Domain Controller.
- Ensured Splunk server was reachable from both Windows machines.
- Confirmed Kali Linux could reach Windows 10 for attack simulation.

---

This setup simulates a small enterprise network with centralized authentication and log monitoring capabilities.

## 🏢 Active Directory Configuration

Active Directory was configured on Windows Server 2022 to simulate an enterprise domain environment.

### 🔹 Domain Controller Setup
![ADDC_Setup](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/games_local.png)
- Installed the **Active Directory Domain Services (AD DS)** role.
- Promoted the server to a Domain Controller.
- Created a new domain:
- Configured DNS automatically during domain promotion.
- Verified domain functionality after server restart.

---

### 🔹 User Account Creation
![useraccount_creation](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/usernames.png)
Using **Active Directory Users and Computers (ADUC)**:

- Created two domain user accounts.
- Assigned secure passwords.
- Verified user objects were properly stored within the domain.

These accounts were later targeted during brute-force simulation.

---

### 🔹 Domain Join (Windows 10 Client)
![domain_joined](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/Domain-joined.png)
- Configured Windows 10 DNS to point to the Domain Controller.
- Joined Windows 10 to the `games.local` domain.
- Restarted the system to complete domain join.
- Successfully logged into Windows 10 using domain user credentials.

---

### 🔹 Verification

- Confirmed Windows 10 appears under domain computers in ADUC.
- Verified successful domain authentication.
- Confirmed authentication logs were generated on the Domain Controller.

---

This configuration established a functional enterprise-style authentication environment, enabling realistic attack simulation and log analysis.

## 📡 Log Forwarding & Splunk Configuration

Splunk Enterprise was deployed on the Ubuntu server to collect, index, and analyze logs from the Windows Server (Domain Controller) and Windows 10 client.

---

### 🔹 Splunk Installation (Ubuntu)
![splunk_installed](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/Splunk_installed.png)
- Installed Splunk Enterprise on Ubuntu.
- Accessed Splunk Web interface via browser.
- Verified Splunk indexing and search functionality.

---

### 🔹 Splunk Universal Forwarder Installation

The Splunk Universal Forwarder was installed on:

- Windows Server 2022 (Domain Controller)
- Windows 10 (Domain Client)

Configuration steps included:

- Specifying Splunk server IP address.
- Configuring receiving port on Splunk.
- Verifying forwarder connectivity.
- Ensuring logs were successfully forwarded.

---

### 🔹 Log Sources Configured
![inputs_conf](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/inputs_conf.png)
The following logs were ingested into Splunk:

- Windows Security Event Logs
- Authentication logs
- Sysmon logs (process creation, PowerShell activity)
- System and Application logs

### 🔹 Log Verification
![logs_verified](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/logs_verification.png)
---

## 🔥 Attack Simulation – Brute Force (Hydra)

To simulate a real-world credential attack scenario, a brute-force attack was performed from the Kali Linux machine targeting domain user accounts in the `games.local` environment.

---

### 🔹 Objective

The objective of this attack simulation was to:

- Generate authentication failure logs.
- Identify detection patterns for brute-force attempts.
- Validate Splunk's ability to detect credential-based attacks.
- Observe successful account compromise behavior.

---

### 🔹 Attack Execution

- Used **Hydra** tool from Kali Linux.
- Targeted domain user accounts.
- Attempted password guessing against Windows authentication service.
- After multiple failed attempts, valid credentials were successfully identified.

This simulated a common credential access technique used by attackers.

---

### 🔹 Windows Security Events Generated
# Brute Force attack performed for user Krshnam:
![krshnam_bruteforce](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/user_krshnam.png)

# Brute Force attack performed for user Arjunam:
![arjunam](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/user_arjunam.png)
The brute-force activity generated the following Windows Event IDs:

- **Event ID 4625** → Failed logon attempt
- **Event ID 4624** → Successful logon (after password discovery)

Multiple 4625 events were observed before a successful 4624 authentication event.

---

### 🔹 Detection in Splunk

In Splunk, the following searches were used:

Failed logon attempts:
index=endpoint EventCode=4625
![endpoint_4625](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/4625_krishnam.png)

Successful logon:
index=endpoint EventCode=4624
![endpoint_4624](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/4624_endpoint.png)
Detection indicators included:

- High volume of failed logons from a single source.
- Repeated attempts against the same user account.
- Successful logon following multiple failures.
- Same source IP address associated with both events.

---

This confirmed that brute-force authentication activity was successfully captured, indexed, and detectable within the SIEM environment.
## 🎯 MITRE ATT&CK Simulation – Atomic Red Team

To simulate post-authentication adversary behavior, Atomic Red Team was deployed on the Windows 10 domain client. This allowed controlled execution of MITRE ATT&CK techniques to validate detection visibility in Splunk.

---

### 🔹 Objective

The objective of this phase was to:

- Simulate real-world adversary techniques.
- Generate process execution and PowerShell logs.
- Validate SIEM visibility beyond authentication events.
- Map observed activity to MITRE ATT&CK framework.

---

### 🔹 Technique Execution

Atomic Red Team was used to execute:

- **T1059.001 – Command and Scripting Interpreter: PowerShell**
- Additional supported techniques for process execution testing.

These simulations generated:

- PowerShell execution logs
- Process creation events
- Sysmon logs (if configured)
- Windows Security Event ID 4688 (Process Creation)

---

### 🔹 Log Analysis in Splunk

The following searches were performed to identify suspicious activity:

Search for PowerShell execution:
![powershell_logs](https://github.com/Varun-hubb/Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM/blob/main/screenshots/powershell_logs.png)

| Technique | ID | Description |
|-----------|----|-------------|
| Command & Scripting Interpreter: PowerShell | T1059.001 | Execution |
| Brute Force | T1110 | Credential Access |

---

This phase demonstrated the ability to simulate adversary behavior and analyze detection artifacts using a structured threat framework.

## 🔐 Security Analysis

This lab successfully demonstrated detection of credential-based attacks and adversary execution techniques within a simulated enterprise Active Directory environment.

---

### 🔹 Credential Access Analysis

The brute-force simulation generated a clear authentication abuse pattern:

- High volume of Event ID 4625 (failed logons)
- Repeated attempts targeting the same account
- Followed by Event ID 4624 (successful logon)

This sequence strongly indicates credential guessing activity and potential account compromise.

Such patterns are commonly associated with:
- Password spraying
- Brute-force attacks
- Unauthorized access attempts

Early detection of these indicators is critical to preventing lateral movement and privilege escalation.

---

### 🔹 Post-Authentication Execution Analysis

Execution of MITRE ATT&CK techniques (T1059.001 – PowerShell) generated:

- Event ID 4688 (process creation)
- PowerShell execution artifacts
- Command-line logging evidence

Monitoring process creation events enables detection of:

- Malicious script execution
- Living-off-the-land techniques
- Suspicious parent-child process chains
- Post-compromise activity

This demonstrates visibility beyond authentication and into attacker behavior after gaining access.

---

### 🔹 Detection Effectiveness

The lab validates:

- Successful log ingestion into Splunk
- Real-time authentication monitoring
- Ability to correlate failed and successful logins
- Detection of suspicious command execution
- Mapping of activity to MITRE ATT&CK framework

The centralized SIEM deployment provided complete visibility across:

- Domain Controller
- Domain Client
- Attack source behavior

---

### 🔹 SOC Relevance

This project reflects real SOC responsibilities:

- Log monitoring
- Event triage
- Pattern recognition
- Attack detection
- Threat behavior mapping
- Investigation using SIEM queries

It demonstrates hands-on experience in identifying authentication abuse and adversary techniques within a domain environment.

## ✅ Conclusion

This project successfully simulated a real-world enterprise Active Directory environment and validated detection capabilities using Splunk SIEM.

Through controlled brute-force attacks and MITRE ATT&CK technique simulations, authentication abuse and post-compromise execution activity were successfully generated, ingested, and analyzed. Key Windows Security Event IDs (4625, 4624, 4688) were investigated to identify attack patterns and validate detection workflows.

The lab demonstrates practical experience in Active Directory administration, SIEM deployment, log analysis, adversary simulation, and SOC-level investigation. It reflects hands-on capability in identifying credential-based attacks and analyzing suspicious process activity within a centralized monitoring environment.

This project strengthens foundational skills required for a SOC Analyst role, including alert triage, event correlation, and threat behavior analysis.

