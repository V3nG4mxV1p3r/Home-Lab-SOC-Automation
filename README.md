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
>
> ### 🚨 Phase 3: Custom Detection Rules & Persistence Hunting
Standard logs are noisy. To build a true early-warning system, I created custom Wazuh rules to detect specific MITRE ATT&CK techniques.

**Scenario: Detecting Malicious Persistence (T1053.005)**
Attackers often use Scheduled Tasks to maintain a foothold in the system. I simulated this by creating a hidden task meant to run with SYSTEM privileges upon logon.

**The Action:**
`schtasks /create /tn "SOC_TEST" /tr "calc.exe" /sc onlogon /ru System`

**The Detection:**
I wrote a custom Level 12 rule in Wazuh to immediately flag any `schtasks.exe` execution containing the `/create` parameter.

<img width="960" height="586" alt="schtasks_exe" src="https://github.com/user-attachments/assets/b886afb1-22c3-45e1-8521-7a70058a7e9e" />


**Analyst Insight:**
By mapping the custom rule to MITRE ATT&CK ID **T1053.005**, the SOC team instantly understands the intent of the attacker (Persistence) without manually deciphering the raw logs.

🎯 Scenario 2: Detecting Ingress Tool Transfer (MITRE T1105) via LOLBins
Objective
To detect and alert on malicious file downloads executed via built-in Windows binaries (LOLBins) such as PowerShell, simulating an attacker attempting to bring tools into the compromised environment stealthily.

🥷 Attack Simulation (Red Team)
Threat actors often use native tools to evade detection. The following command was executed on the Windows 10 endpoint to bypass execution policies and download a fake payload (svchost_update.exe) to the C:\Users\Public folder:
```powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/wazuh/wazuh/master/LICENSE' -OutFile 'C:\Users\Public\svchost_update.exe'"```

🛡️ Detection Engineering (Blue Team)
Sysmon was configured to capture Event ID 11 (File Create). The telemetry was forwarded to Wazuh. A custom rule was created to trigger a Critical (Level 12) alert when powershell.exe drops a specific suspicious executable.

Custom Wazuh Rule (local_rules.xml):
```
<rule id="100003" level="12">
    <if_group>sysmon</if_group>
    <field name="win.eventdata.image">powershell.exe</field>
    <field name="win.eventdata.targetFilename">svchost_update.exe</field>
    <description>CRITICAL: PowerShell Downloaded Suspicious Executable to Public Folder (T1105)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>
```
  📸 Evidence of Detection
  
  <img width="770" height="565" alt="alerts_wazuh" src="https://github.com/user-attachments/assets/a8599bf1-491a-4f10-aaf3-304983539e7a" />

  <img width="627" height="370" alt="rule_level12" src="https://github.com/user-attachments/assets/1c2d83a1-07af-41e7-8b0a-f43570366cc7" />

🎯 Scenario 3: Privilege Escalation via Windows Services (MITRE T1543.003)
Objective
To detect when an attacker uses native Windows tools (sc.exe) to create a persistent, malicious service running with SYSTEM privileges.

🥷 Attack Simulation
```sc.exe create &quot;Windows_Update_Backdoor&quot; binPath= &quot;C:\Users\Public\svchost_update.exe&quot; start= auto obj= &quot;LocalSystem&quot;```

🛡️ Detection Engineering
Default SIEM rules may ignore sc.exe to prevent false positives. A custom rule was created to trigger a Critical alert when sc.exe is specifically used to create a service.

Custom Wazuh Rule:
```
&lt;rule id=&quot;100004&quot; level=&quot;12&quot;&gt;
    &lt;if_group&gt;sysmon&lt;/if_group&gt;
    &lt;field name=&quot;win.system.eventID&quot;&gt;1&lt;/field&gt;
    &lt;field name=&quot;win.eventdata.image&quot;&gt;sc\.exe&lt;/field&gt;
    &lt;field name=&quot;win.eventdata.commandLine&quot;&gt;create&lt;/field&gt;
    &lt;description&gt;CRITICAL: Suspicious Service Creation via SC.EXE (Privilege Escalation - T1543.003)&lt;/description&gt;
    &lt;mitre&gt;
      &lt;id&gt;T1543.003&lt;/id&gt;
    &lt;/mitre&gt;
  &lt;/rule&gt;
```

🎯 Scenario 4: OS Credential Dumping via LSASS Memory (MITRE T1003.001)
Objective
To detect stealthy credential harvesting attempts where attackers dump the lsass.exe process memory using the native comsvcs.dll LOLBin.

🥷 Attack Simulation
```rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [LSASS_PID] C:\Users\Public\lsass_dump.dmp full```

🛡️ Detection Engineering
Sysmon Event ID 1 (Process Create) captures the execution. The custom rule strictly looks for the MiniDump command line argument passed to rundll32.exe.

Custom Wazuh Rule:
```
&lt;rule id=&quot;100005&quot; level=&quot;12&quot;&gt;
    &lt;if_group&gt;sysmon&lt;/if_group&gt;
    &lt;field name=&quot;win.eventdata.commandLine&quot;&gt;MiniDump&lt;/field&gt;
    &lt;description&gt;CRITICAL: LSASS Memory Dump Attempt via comsvcs.dll LOLBin (Credential Access - T1003.001)&lt;/description&gt;
    &lt;mitre&gt;
      &lt;id&gt;T1003.001&lt;/id&gt;
    &lt;/mitre&gt;
  &lt;/rule&gt;
```
