# 🛡️ SOC Home Lab: Wazuh SIEM & Attack Detection

## 🚀 Project Overview
In this project, I built a fully functional **Security Operations Center (SOC)** environment to simulate real-world cyber attacks and practice **Threat Detection & Incident Response**.

I deployed **Wazuh SIEM** to monitor a Windows 10 endpoint and used **Kali Linux** to execute offensive operations (Network Scanning & Brute Force), successfully detecting and analyzing the resulting security logs.

## 🏗️ Architecture
* **SIEM:** Wazuh Server (Ubuntu Server 24.04) running on VirtualBox.
* **Victim Endpoint:** Windows 10 Enterprise (with Wazuh Agent).
* **Attacker:** Kali Linux (Nmap, Hydra, Manual Scripts).
* **Network:** Isolated NAT Network (`10.0.2.0/24`) for safe simulation.

## ⚡ Scenarios & Detection

### Scenario 1: Brute Force Attack Detection
* **Attack:** Attempted unauthorized RDP/Login access using incorrect passwords multiple times.
* **Detection:** Wazuh triggered `Authentication failure` alerts (Event ID 4625).
* **Analysis:** Identified the source of the attack and the targeted usernames.

### 🕵️‍♂️ Analyst View: Deep Dive into Logs
Below is the detailed analysis of the captured security event in Wazuh dashboard.

![Wazuh Log Analysis] <img width="867" height="990" alt="Wazuh-BruteForce-Log-Analysis-EventID4625" src="https://github.com/user-attachments/assets/0e96dc21-ce11-4678-93fd-92d798feb79d" />


**Technical Breakdown of the Alert:**
* **Event ID:** `4625` (An account failed to log on).
* **Significance:** Multiple occurrences of this event within a short timeframe indicate a **Brute Force** attempt.
* **Target User:** `vboxuser` (The attacker attempted to guess the password for this specific account).
* **Logon Type:** `2` (Interactive). This indicates the attack was performed locally on the machine (simulated via manual entry at the lock screen).
* **Outcome:** The SIEM successfully parsed the raw Windows Event log and alerted the SOC dashboard instantly.

## 🔧 Skills Demonstrated
* **SIEM Configuration:** Deployment and agent integration of Wazuh.
* **Log Analysis:** Interpreting Windows Security Events (Event Viewer).
* **Virtualization:** Managing isolated lab environments with VirtualBox.
* **Blue Team Operations:** From attack simulation to log visibility.

* ---

## 🔍 Phase 2: Telemetry & Forensic Visibility (Sysmon)

Standard Windows logs weren't enough, so I integrated **Sysmon** to get deeper visibility into system activities.

### Test Case: Detecting Encoded PowerShell Execution
Attackers often use Base64 encoding to hide their malicious commands. I simulated this by running an encoded command in the Windows 10 VM.

* **Action:** Executed a PowerShell script using `-EncodedCommand`.
* **Detection:** Sysmon captured the **Event ID 1 (Process Creation)**.
* **Analysis:** Even though the command was obfuscated, the Sysmon logs in Wazuh allowed me to see the full command-line arguments and the parent process.

#### Evidence of Detection:
![Sysmon PowerShell Log]<img width="1099" height="691" alt="sysmon_powershell_log" src="https://github.com/user-attachments/assets/c369deb1-d193-41ba-bbb1-f8c72f86d3db" />


> **Analyst Note:** This level of visibility is crucial for detecting "Living off the Land" (LotL) attacks where legitimate tools like PowerShell are used for malicious purposes.
