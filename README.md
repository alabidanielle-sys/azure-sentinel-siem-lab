# Azure SIEM Lab: Detecting and Mapping Real-World Attacks with Microsoft Sentinel

A hands-on live Azure lab that walks through building a cloud-based Security Operations Center (SOC) environment from scratch — deploying a deliberately exposed Windows 11 virtual machine as a honeypot, ingesting its security logs into Microsoft Sentinel, and using KQL queries and a geolocation workbook to visualize real brute force attacks happening in real time from around the world.

---

## What This Lab Covers

- Creating an Azure resource group and virtual network
- Deploying a Windows 11 Pro virtual machine in Microsoft Azure
- Intentionally exposing the VM to the internet by removing firewall and NSG restrictions
- Observing real-world brute force attacks through Windows Event Viewer
- Setting up a Log Analytics Workspace to collect and store security logs
- Onboarding Microsoft Sentinel as the SIEM
- Installing the Windows Security Events data connector and creating a Data Collection Rule
- Writing KQL queries to filter and analyze failed logon events
- Creating a GeoIP watchlist to enrich attacker IP addresses with location data
- Building a Microsoft Sentinel Workbook that plots attacker origins on a live world map
- Applying the NIST Incident Response framework to document and analyze what happened

---

## Lab Environment

| Component | Details |
|---|---|
| Cloud Platform | Microsoft Azure (Free Trial — $200 USD credit) |
| Virtual Machine | TRIN-EAST-03 — Windows 11 Pro |
| VM Size | Standard D2ads v6 — 2 vCPUs, 8 GiB RAM |
| Virtual Network | DVnet-Soc-Lab |
| Resource Group | Dan-SOC-Lab (East US 2) |
| Log Analytics Workspace | DAN-LAW-SOC-Lab |
| SIEM | Microsoft Sentinel |
| Query Language | KQL (Kusto Query Language) |
| Public IP | 48.211.170.224 |

---

## Step-by-Step Walkthrough

### 1. Creating the Resource Group and Virtual Network

I logged into the Azure portal and created a resource group called `Dan-SOC-Lab` in the East US 2 region. A resource group is just a container that keeps all the related pieces of a project organized and easy to clean up when you're done.

Next I created a virtual network called `DVnet-Soc-Lab` inside that resource group — this is the network the VM would live on.

![Create Resource Group](Screenshot%20(352).png)

![Resource Group Created](Screenshot%20(353).png)

![Create Virtual Network](Screenshot%20(354).png)

![Virtual Network Deployed](Screenshot%20(355).png)

---

### 2. Deploying the Virtual Machine

With the network in place, I created a Windows 11 Pro virtual machine named `TRIN-EAST-03`. I selected Standard D2ads v6 — 2 vCPUs and 8 GiB of RAM — and configured an administrator account under the username `a-smaki`. The OS disk was set to 127 GiB Premium SSD and the VM was placed on the DVnet-Soc-Lab network.

Once deployment completed, the resource group contained the VM, a public IP address (`48.211.170.224`), a network security group, a network interface, and the OS disk.

![Create VM - Size and Admin](Screenshot%20(359).png)

![Create VM - Disk Config](Screenshot%20(360).png)

![VM Deployment Complete](Screenshot%20(361).png)

![Resource Group Overview](Screenshot%20(362).png)

---

### 3. Opening the VM to the Internet (Honeypot Configuration)

This is the part that makes the lab work — and the part that would be a serious security incident in a real environment.

By default, Azure creates an NSG rule that restricts inbound RDP traffic. I deleted that default RDP rule from `TRIN-EAST-03-nsg` and replaced it with a new inbound rule called `DANGER_AllowAn...` set to priority 100, allowing **any** traffic from **any** source on **any** port. This removes every protection from the machine and lets the internet find it.

I then connected to the VM over RDP, opened Windows Defender Firewall with Advanced Security, and turned the firewall state to **Off** for the Domain Profile. The VM was now fully exposed to the public internet with no defenses.

![Deleting RDP Rule from NSG](Screenshot%20(364).png)

![DANGER Rule - All Traffic Allowed](Screenshot%20(365).png)

![VM Overview - Running](Screenshot%20(366).png)

![RDP Connection](Screenshot%20(367).png)

![RDP Credentials](Screenshot%20(368).png)

![Disabling Windows Defender Firewall](Screenshot%20(371).png)

---

### 4. Watching the Attacks Roll In — Event Viewer

Within minutes of the VM going live, I opened Event Viewer on the machine and filtered the Security log for **Event ID 4625** — failed logon attempts. The volume was immediate:

- **Total security events logged:** 34,421
- **Event ID 4625 (failed logons):** 34,279

The failed attempts were coming in continuously — automated bots scanning the internet for exposed RDP endpoints and hammering them with common username and password combinations. The event details showed `Security ID: NULL SID`, confirming these weren't domain accounts — just attackers cycling through credential wordlists.

I also checked **Event ID 4624** (successful logons) in Event Viewer to confirm no attacker had actually gotten in. All successful logons showed `Security ID: SYSTEM` — Windows logging its own internal service activity, which is completely normal. No unauthorized access occurred.

![Event Viewer - 4625 Failed Logons](Screenshot%20(374).png)

![Event Viewer - 4625 Detail](Screenshot%20(375).png)

---

### 5. Creating the Log Analytics Workspace

To get the VM's logs into Sentinel, I first needed somewhere to store them. I created a Log Analytics Workspace called `DAN-LAW-SOC-Lab` in the Dan-SOC-Lab resource group in East US 2. This workspace is the central log storage and query engine for the whole lab.

![Create Log Analytics Workspace](Screenshot%20(377).png)

![Log Analytics Workspace Deployed](Screenshot%20(379).png)

---

### 6. Onboarding Microsoft Sentinel

With the workspace ready, I navigated to Microsoft Sentinel in the Azure portal and added it to `DAN-LAW-SOC-Lab`. Sentinel offers a 31-day free trial. Once onboarded, it became the SIEM layer sitting on top of the workspace — the place where I'd do all the detection and visualization work.

![Add Sentinel to Workspace](Screenshot%20(380).png)

---

### 7. Installing the Windows Security Events Connector

Inside Sentinel's Content Hub, I searched for "security events" and found the **Windows Security Events** solution (v3.0.12 by Microsoft). I selected the **Windows Security Events via AMA** connector — the Azure Monitor Agent approach, which is Microsoft's current recommended method for ingesting Windows security logs into Sentinel.

I then created a **Data Collection Rule** to wire the VM's logs to the workspace:

| Setting | Value |
|---|---|
| Rule Name | DCR-Windows-Security-Logs |
| Resource Group | Dan-SOC-Lab |
| Target Resource | trin-east-03 |
| Events to Collect | All Security Events |

After validation passed, the rule was created and the connector began pulling logs from `TRIN-EAST-03` into the workspace.

![Content Hub - Windows Security Events](Screenshot%20(383).png)

![Windows Security Events Connector](Screenshot%20(384).png)

![Create Data Collection Rule - Collect Tab](Screenshot%20(386).png)

![Create Data Collection Rule - Basic Tab](Screenshot%20(387).png)

![Data Collection Rule - Review and Create](Screenshot%20(388).png)

---

### 8. Querying Logs with KQL

With logs flowing in, I opened the Logs blade inside `DAN-LAW-SOC-Lab` and wrote KQL queries to explore what was being captured.

**Basic query — all security events:**
```kql
SecurityEvent
```
This confirmed logs were coming in from `TRIN-EAST-03`, with accounts like `\POS`, `\ADMINISTRATOR`, `\MASTER`, `\DAVID`, and `\FTP` visible immediately — all failed logon attempts from external attackers.

**Filtering for failed logons only:**
```kql
SecurityEvent
| where EventID == 4625
```
This returned 86 results. Expanding an individual record revealed the full event detail — TenantId, SourceSystem (OpsManager), EventSourceName (Microsoft-Windows-Security-Auditing), and Channel (Security).

**Time-filtered query with IP projection:**
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
| order by TimeGenerated desc
```
This version surfaces attacker IP addresses alongside the account names they tried — the foundation for the geolocation map. The exported CSV of these results is included in this repository.

![Log Analytics - SecurityEvent Query](Screenshot%20(391).png)

![Log Analytics - EventID 4625 Filter](Screenshot%20(392).png)

![Log Analytics - 4625 with IP Projection](Screenshot%20(393).png)

---

### 9. Creating the GeoIP Watchlist

To plot attacker IPs on a map I needed to enrich them with location data. I created a Sentinel Watchlist called `geoip` via the Watchlist wizard in Microsoft Defender and uploaded a local CSV containing 49 GeoIP records — latitude, longitude, city, country, and network range data.

| Setting | Value |
|---|---|
| Name | geoip |
| Alias | geoip |
| Source Type | Local |
| File Type | Text/CSV |
| Search Key | network |

Once submitted, the 49 items were validated and made available in KQL via `_GetWatchlist("geoip")`.

![Watchlist Wizard - General](Screenshot%20(397).png)

![Watchlist Review and Create](Screenshot%20(398).png)

![Watchlist Created Successfully](Screenshot%20(399).png)

---

### 10. Building the Attack Map Workbook

The final step was creating a Microsoft Sentinel Workbook to visualize where the attacks were coming from on a world map.

I created a new workbook in Sentinel and opened the Advanced Editor. I pasted in a JSON configuration that defines a map visualization. The core KQL logic:

1. Loads the geoip watchlist with `_GetWatchlist("geoip")`
2. Pulls Event ID 4625 failed logon records from `SecurityEvent`
3. Uses `ipv4_lookup` to match attacker IPs against the GeoIP network ranges
4. Summarizes the failure count by IP address, city, country, latitude, and longitude
5. Projects `FailureCount`, `AttackerIp`, `latitude`, `longitude`, `city`, `country`, and a `friendly_location` label

The `map.json` configuration file is included in this repository.

After applying the configuration, the workbook rendered a live world map with two attack clusters:

- **Milton Keynes, United Kingdom** — 108 failed logon attempts from IP `82.67.135.231` (large red dot)
- **Hyderabad, India** — 44 failed logon attempts from IP `103.212.182.194` (smaller green dot)

Only two source IPs appeared on the map — and looking at the exported log data, that's exactly right. Every single one of the 86 recorded attempts came from one of those two addresses. These weren't random humans — they were automated bots running on a schedule, cycling through credential wordlists roughly once per minute. The UK bot favored corporate-sounding usernames (DISPATCH, SHIPPING, FRONTDESK1, SQLSERVICE, PURCHASING) while the India bot cycled through ADMIN, USER, PC, ADMINISTRATOR, and A on a tight rotation.

![map.json Configuration File](Screenshot%20(400).png)

![Workbook Advanced Editor](Screenshot%20(401).png)

![Attack Map - Milton Keynes Detail](Screenshot%20(403).png)

![Attack Map - Full View](Screenshot%20(404).png)

---

## Incident Response Analysis (NIST Framework)

Even though this VM was deliberately exposed as a honeypot, walking through a proper incident response process is still valuable — and in a real SOC, a honeypot that gets hit still follows IR procedures. The goal is to document what happened, confirm the scope of the incident, and extract any useful threat intelligence. This section applies the NIST IR framework (Preparation → Detection & Analysis → Containment → Eradication & Recovery → Post-Incident Activity) to this specific lab scenario and is honest about which steps were completed, which were skipped, and why that matters.

---

### Phase 1 — Preparation ✅ Completed

Preparation happened before the attack even started. Logging was enabled on the VM, a Log Analytics Workspace was configured, and Microsoft Sentinel was onboarded with a Data Collection Rule actively ingesting security events. This meant that when attacks began, there was already a pipeline in place to capture everything. Without this groundwork, none of the detection work in later phases would have been possible.

In a real environment, preparation would also include a documented IR plan, defined roles and escalation paths, and baseline logging of normal activity to compare against during an incident.

---

### Phase 2 — Detection & Analysis ✅ Completed

This phase was the core of the lab. The attack was detected through Event Viewer (Event ID 4625 — failed logon) and confirmed at scale through KQL queries in Log Analytics. Analysis revealed:

- **34,279 failed logon attempts** in a single session
- **Two source IPs** responsible for all recorded attacks: `82.67.135.231` (Milton Keynes, UK) and `103.212.182.194` (Hyderabad, India)
- Automated, bot-driven behavior confirmed by the consistent ~60-second interval between attempts and the use of credential wordlists
- **No successful unauthorized logons** — verified by querying Event ID 4624 and confirming all successful logons were `NT AUTHORITY\SYSTEM` machine-level events

**Threat Intelligence Lookup — completed post-lab:**

Both attacker IPs were looked up on AbuseIPDB after the lab concluded. The results confirmed what the attack behavior already suggested — both IPs are known malicious actors with prior abuse reports from other users across the internet.

| IP | AbuseIPDB Reports | Confidence of Abuse | ISP | Usage Type | Country (AbuseIPDB) |
|---|---|---|---|---|---|
| `82.67.135.231` | 65 reports | 53% | Proxad / Free SAS | Fixed Line ISP | France (Paris) |
| `103.212.182.194` | 41 reports | 46% | SAN | Data Center / Web Hosting / Transit | Thailand (Bangkok) |

![AbuseIPDB - 103.212.182.194](Screenshot%20(406).png)

![AbuseIPDB - 82.67.135.231](Screenshot%20(405).png)

**Why the locations differ from the attack map:**

The attack map (built from the GeoIP watchlist CSV) showed Milton Keynes, UK and Hyderabad, India. AbuseIPDB shows Paris, France and Bangkok, Thailand for the same IPs. This discrepancy is expected and worth understanding — it comes down to how GeoIP databases work.

GeoIP databases map IP address ranges to locations based on where ISPs and organizations register those ranges, not where the traffic is physically coming from. Different GeoIP providers use different data sources and update cycles, so the same IP can resolve to different cities or even different countries depending on which database you query. Neither result is necessarily "wrong" — they reflect different snapshots of registration data.

The `103.212.182.194` result is particularly interesting. AbuseIPDB classifies its usage type as **Data Center / Web Hosting / Transit**, registered to an ISP called SAN. This strongly suggests the attacker was using a **rented VPS** (virtual private server) as attack infrastructure rather than attacking from their own home connection — a common tactic that makes attribution harder and explains why the GeoIP location and AbuseIPDB location diverge. The attacker's actual physical location is unknown.

`82.67.135.231` resolves to a French residential ISP (Proxad/Free SAS), suggesting either a compromised home machine being used as part of a botnet, or someone in France running attack tools directly.

Documenting these findings as **Indicators of Compromise (IOCs)** is standard SOC practice. Both IPs, their reported abuse history, and the attack timestamps would be added to a threat intelligence feed or used to create detection rules to alert if either IP is seen again.

---

### Phase 3 — Containment ⚠️ Partially Completed

Containment means stopping the attack from spreading or causing further damage. In this lab, the VM was shut down — which effectively ended the attack — but containment ideally should have happened in this order:

1. **Block the attacker IPs at the NSG level first** — add a deny rule in `TRIN-EAST-03-nsg` for both `82.67.135.231` and `103.212.182.194` before shutting anything down. This stops the attack while keeping the machine running and preserving forensic evidence.
2. **Isolate the network interface** — in Azure you can detach the public IP from the VM without shutting it down, cutting internet access while keeping the machine available for investigation.
3. **Shut down the VM** — only after evidence has been preserved.

What actually happened: the VM was shut down first, which was the right call from a cost management perspective but skipped steps 1 and 2. No evidence of a breach was found (all 4624 events were SYSTEM logons), so in this specific case nothing critical was lost — but in a real incident with an active compromise, shutting down first would destroy volatile memory and potentially overwrite evidence.

---

### Phase 4 — Eradication & Recovery ✅ Not Applicable (No Breach)

Since no attacker successfully authenticated, there was nothing to eradicate — no malware dropped, no persistence mechanisms established, no accounts compromised. Verification came from the 4624 query confirming only SYSTEM-level logons occurred.

In a scenario where a breach had occurred, eradication would involve removing any attacker-installed tools or accounts, reimaging the VM from a clean snapshot, rotating any credentials that were targeted, and hardening the NSG before bringing the machine back online.

---

### Phase 5 — Post-Incident Activity ⚠️ Partially Completed

**What was completed:**
- Attack data exported as `query_data.csv` and retained as evidence
- Attack map screenshot captured documenting attacker origins
- `map.json` workbook configuration saved
- This readme documents the full timeline and findings

**What was skipped and should have been done:**
- **Exporting the full Event Viewer `.evtx` log** from the VM before shutdown — this contains the complete unfiltered security log, not just what was forwarded to Log Analytics
- **Formal IOC documentation** — a structured record of the two attacker IPs, the usernames they attempted, the time window, and attack frequency, formatted for use in future detection rules
- **Threat intel lookups** on both IPs (AbuseIPDB, VirusTotal, Shodan) as described in Phase 2
- **Sentinel Analytics Rule** — creating an automated alert rule in Sentinel so that if this pattern (high volume of 4625 events from a single IP) occurred again, an incident would be created automatically without requiring manual investigation

**Key lesson:** The fact that the VM was intentionally vulnerable does not make incident response optional. The honeypot produced real attacker data, real IOCs, and a real opportunity to practice the full IR cycle. Stopping the VM to manage costs before completing IR is an understandable trade-off in a personal lab — but recognizing that the trade-off was made, and knowing what the correct process looks like, is exactly the kind of operational awareness that matters in a real SOC role.

---

## Key Concepts Practiced

- How quickly an exposed RDP endpoint attracts automated attacks — in this lab, within minutes
- Reading and filtering Windows Security Event logs using Event IDs 4625 (failed logon) and 4624 (successful logon), and understanding the difference between system logons and external ones
- How a Log Analytics Workspace, Microsoft Sentinel, and a data connector fit together as a log ingestion pipeline
- Writing KQL queries to filter by event ID, time range, and project specific fields including attacker IP addresses
- Enriching raw IP data using a GeoIP watchlist and `ipv4_lookup` to add geographic context
- How a SIEM workbook can turn raw log data into an actionable visual — in this case a real-time geolocation attack map
- Recognizing automated credential stuffing behavior: consistent timing intervals, wordlist-style usernames, and a small number of persistent source IPs generating thousands of attempts

---

## Notes

> **On incident response:** After observing the attack data, I shut the VM down promptly to stop Azure charges from accumulating. In hindsight, proper IR procedure should have come first — exporting Event Viewer logs, documenting attacker IPs and usernames as indicators of compromise, and verifying no unauthorized access had succeeded before pulling the plug. Stopping the VM immediately can destroy volatile forensic artifacts that would matter in a real incident. It's a useful reminder that cost management instincts and IR discipline can conflict, and IR should win.

- The exported CSV of Event ID 4625 log results is included in this repository (`query_data.csv`)
- The Sentinel Workbook JSON configuration is included as `map.json`
- All attacks came from two source IPs: `82.67.135.231` (UK) and `103.212.182.194` (India)
- The VM was deleted after the lab to stop billing
- Lab follows the Josh Madakor Azure SOC tutorial: https://youtu.be/g5JL2RIbThM
