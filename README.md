# Active-Directory-Attack-Detection-Lab-using-Splunk-SIEM

## Project Overview

This project simulates a real-world enterprise Active Directory environment to demonstrate attack detection and log analysis using Splunk SIEM. A multi-VM lab was built consisting of a Domain Controller (Windows Server 2022), a domain-joined Windows 10 client, a Splunk server (Ubuntu), and an attacker machine (Kali Linux).

The lab focuses on detecting authentication-based attacks and adversary techniques. A brute-force attack was conducted using Hydra to compromise domain user accounts, generating Windows Security Event IDs 4625 (failed logon) and 4624 (successful logon), which were analyzed in Splunk.

Additionally, Atomic Red Team was used to simulate MITRE ATT&CK techniques such as PowerShell execution (T1059.001), allowing further validation of detection visibility through Sysmon and Windows Event Logs.

This project demonstrates hands-on experience in Active Directory administration, SIEM log ingestion, attack simulation, and SOC-level security analysis.

## 🏗️ Lab Architecture
### 🔹 Architecture Diagram

(Add your architecture image below)

```markdown
![Lab Architecture](screenshots/architecture.png)
```
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

