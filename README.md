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

The following logs were ingested into Splunk:

- Windows Security Event Logs
- Authentication logs
- Sysmon logs (process creation, PowerShell activity)
- System and Application logs

---

### 🔹 Log Verification

To confirm successful ingestion, the following searches were performed:

Search for failed logons:
