# 🛡️ Incident Handling with Splunk 

> **Summary:** Investigated a simulated attack on `imreallynotbatman.com` using Splunk logs, mapped attacker actions to the Cyber Kill Chain, and leveraged OSINT to enrich findings. Identified reconnaissance, exploitation, installation, C2, and defacement activities through Splunk searches.

---

## 🎯 Objectives
- Use Splunk to investigate suspicious logs  
- Map attacker activity to **Cyber Kill Chain phases**  
- Leverage OSINT platforms (VirusTotal, Robtex, ThreatMiner, Hybrid Analysis)  
- Understand host-centric vs network-centric log sources  
- Perform effective Splunk searches to answer investigation questions  

---

## 🛠️ Environment
- Platform: TryHackMe — *Incident Handling with Splunk* room  
- Tool: **Splunk Enterprise**  
- Dataset: `index=botsv1` (event logs, sysmon, suricata, fortigate_utm, win event logs)  
- Scenario: SOC Analyst investigating anomalies in Wayne Enterprise’s web server (`imreallynotbatman.com`)  

---

## 🚀 Workflow & Findings

### 🔎 Reconnaissance Phase
- Identified attacker scanning activity.  
- CVE alert triggered by Suricata.  
- Discovered Joomla CMS backend in server logs.  
- Found web scanner used: **Acunetix**.  
- Attacker IP observed: **40.80.148.42**.  

---

### 💥 Exploitation Phase
- Tracked brute-force login attempts on `/joomla/administrator/index.php`.  
- Notable Splunk searches:
  ```spl
  index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST
  index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data
  index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" | table src_ip creds http_user_agent uri
#### Findings:
- Attacker brute-forced user `admin`.
- Password spraying attempts from IP `23.22.63.114`.
- ~142 unique brute-force attempts → successful login.
---
### 🖥️ Installation Phase
- Detected uploaded malicious executable 3791.exe.
- Log sources: Sysmon, WinEventLog, fortigate_utm.
- Verified execution with Sysmon EventCode=1:
- ```spl
  index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1
- Extracted MD5 hash for further analysis.
---
### 🎯 Action on Objectives
- Web server defaced with file: <b>poisonivy-is-coming-for-you-batman.jpeg</b>.
- Splunk search revealed suspicious download from attacker-controlled domain:
- ```spl
  index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url
- Domain: `prankglassinebracket.jumpingcrab.com`.
---
### 🌐 Command & Control Phase
- Observed attacker using <b>Dynamic DNS</b> for malicious infra.
- DNS queries captured in `stream:dns` logs confirmed C2 traffic.
---
### ⚔️ Weaponization & Delivery Phases
- Used OSINT (Robtex, VirusTotal, ThreatMiner, Hybrid-Analysis).
#### Findings:
- Associated malware: `MirandaTateScreensaver.scr.exe` (MD5: `c99131e0169171935c5ac32615ed6261`).
- Attacker email: `Lillian.rose@po1s0n1vy.com`.
- Multiple masquerading domains tied to attacker IPs.

---

## ✅ Outcome
Successfully mapped attacker lifecycle across Cyber Kill Chain phases.
Leveraged Splunk searches to uncover brute force, malware upload, C2, and defacement activities.
Validated findings with OSINT platforms to enrich context.

---

## 🧩 Skills Demonstrated
Splunk search queries for log analysis
Regex extraction within Splunk queries (rex)
Cyber Kill Chain methodology for incident mapping
Correlation of host-centric and network-centric logs
Enrichment with OSINT tools (VirusTotal, Robtex, ThreatMiner, Hybrid Analysis)
