# BOTSv3 (Splunk) — SOC Investigation Report (Q1–Q8)

This repository contains a SOC-style investigation write-up for **Splunk Boss of the SOC v3 (BOTSv3)** covering **300-level questions Q1–Q8**, including SPL queries, evidence references (Figures 1–14), and SOC interpretation + next steps.

---

## Table of Contents
- [1. SOC context, scenario and investigation goals](#1-soc-context-scenario-and-investigation-goals)
  - [1.1 SOC context](#11-soc-context)
  - [1.2 BOTSv3 scenario](#12-botsv3-scenario)
  - [1.3 Goals, scope and assumptions](#13-goals-scope-and-assumptions)
- [2. SOC roles and incident handling reflection](#2-soc-roles-and-incident-handling-reflection)
  - [2.1 Tiered responsibilities in this investigation](#21-tiered-responsibilities-in-this-investigation)
  - [2.2 Incident handling lifecycle mapping](#22-incident-handling-lifecycle-mapping)
- [3. Splunk deployment, onboarding, and data validation](#3-splunk-deployment-onboarding-and-data-validation)
  - [3.1 Deployment rationale (SOC view)](#31-deployment-rationale-soc-view)
  - [3.2 Data ingestion and readiness checks](#32-data-ingestion-and-readiness-checks)
- [4. Guided questions Q1–Q8](#4-guided-questions-q1q8)
  - [4.1 Summary table](#41-summary-table)
  - [4.2 Detailed analysis](#42-detailed-analysis)
- [5. Conclusion](#5-conclusion)
  - [5.1 Chain-of-evidence narrative](#51-chain-of-evidence-narrative)
  - [5.2 Detection engineering recommendations (SOC strategy)](#52-detection-engineering-recommendations-soc-strategy)
  - [5.3 Response playbook improvements](#53-response-playbook-improvements)
- [References](#references)
- [Appendix](#appendix)

---

## 1. SOC context, scenario and investigation goals

### 1.1 SOC context
A **Security Operations Centre (SOC)** is responsible for maintaining continuous security visibility, detecting abnormal behaviour, and coordinating incident response. Modern SOC work depends on correlating signals across identity, endpoint, email, cloud, and network domains. In real environments, analysts must be able to:
- move quickly from a weak signal to stronger evidence,
- confirm what happened, and
- propose containment + improvement actions that reduce risk going forward.  
[1]

### 1.2 BOTSv3 scenario
**Boss of the SOC v3 (BOTSv3)** is a Splunk-provided dataset/training environment that simulates an incident inside a fictitious company (**Frothly**). It includes multiple log sources such as:
- Microsoft 365 (cloud audit / management activity),
- SMTP traffic (email delivery and attachments),
- Sysmon (high-fidelity endpoint telemetry),
- Windows Security auditing (identity and privilege changes),
- osquery (endpoint state and process/network observations).

This mix is similar to what a SOC ingests in practice: cloud audit + email telemetry for entry, endpoint telemetry for execution and persistence, and identity telemetry for privilege escalation.  
[2]

### 1.3 Goals, scope and assumptions

#### Goals
1. Demonstrate a SOC-style workflow: validate Splunk access, confirm dataset visibility, and verify sources needed for investigation.
2. Answer BOTSv3 Q1–Q8 using SPL queries and evidence.
3. Translate each answer into SOC meaning (what it suggests, why it matters, what to do next).

#### Scope
- This report covers only **300-level questions Q1–Q8** using the evidence in **Figures 1–14**.

#### Assumptions
- Parsed fields shown in Splunk are accurate (timestamps and sourcetypes are correctly interpreted).
- BOTSv3 is treated as “ground truth telemetry” suitable for incident reconstruction, without performing external host forensics.

---
## 2. SOC roles and incident handling reflection

### 2.1 Tiered responsibilities in this investigation
SOC work is commonly separated into tiers:

**Tier 1 (Monitoring & triage)**
- Identify unusual behaviour, confirm whether it deserves escalation, and collect initial context (account, host, time window, key indicators).
- In BOTSv3, Tier 1 work includes recognising unusual User-Agent strings, suspicious attachments, and unusual ports.

**Tier 2 (Investigation & response)**
- Build a timeline across sources, determine the extent of compromise, confirm attacker actions (persistence, privilege escalation), and produce actionable response steps.
- In this case, Tier 2 correlation connects macro-enabled delivery → suspicious process → account creation → admin membership → listening service.

**Tier 3 (Detection engineering & threat hunting)**
- Convert what was learned into improved detections, dashboards, and response playbooks.
- For this dataset, that means creating correlation searches such as “new account + admin group add within 30 minutes,” and tuning baselines for rare User-Agents.

### 2.2 Incident handling lifecycle mapping
This investigation aligns with a standard incident handling lifecycle:

**Preparation (Prevent/Ready)**
- Ensure Splunk is operational, data is ingested, and key sourcetypes are available. Without this, later questions cannot be answered reliably.

**Detection & analysis**
- Identify indicators in cloud/email logs and confirm behavioural evidence in endpoint/identity logs.

**Containment & eradication**
- Derive what an analyst would do in a real SOC: isolate affected hosts, disable malicious accounts, remove elevated privileges, block hashes, and search for lateral spread.  
[1]

**Recovery & lessons learned**
- Strengthen correlation logic, tune alerting thresholds, and improve visibility gaps (e.g., ensure group management auditing is enabled and consistently monitored).  
[5]

---

## 3. Splunk deployment, onboarding, and data validation

### 3.1 Deployment rationale (SOC view)
The environment was run via a **VM-based setup**, reflecting SOC lab practice because it supports:
- repeatability (snapshots and stable configuration),
- isolation (safe testing without affecting production),
- controlled resource allocation.

**Operational evidence**
- Splunk web login page reachable (Fig. 1).
- VirtualBox VM exists and was used for BOTSv3 work (Fig. 2).

### 3.2 Data ingestion and readiness checks
A SOC analyst should not begin investigation until the following are verified:

**(A) Index visibility** — `index=botsv3 | head 10`  
**(B) Required sourcetype presence** — `index=botsv3 sourcetype="ms:o365:management" | head 5` ; `index=botsv3 sourcetype="stream:smtp" | head 5` ; `index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | head 5` ; `index=botsv3 sourcetype="WinEventLog:Security" | head 5` ; `index=botsv3 sourcetype="osquery:results" | head 5`  
**(C) Field sanity examples** — `index=botsv3 sourcetype="WinEventLog:Security" EventCode=4720 | table _time host Account_Name EventCode` ; `index=botsv3 sourcetype="osquery:results" | table _time host name columns.cmdline columns.uid columns.owner_uid`

In a SOC, incorrect sourcetype parsing or time parsing breaks correlation and can cause false conclusions. In this assessment, successful search results across each domain (Figures 3–10) indicate that the dataset is sufficiently prepared for analysis.

---
## 4. Guided questions Q1–Q8

### 4.1 Summary table

| Q  | What was identified | Final Answer | Log source (domain) | Evidence |
|---:|---|---|---|---|
| Q1 | Suspicious User-Agent | `Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4` UA string | O365 management (cloud) | Fig. 3 |
| Q2 | Malicious attachment filename | `Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm` | SMTP (email) | Fig. 4 |
| Q3 | Suspicious executable | `HxTsr.exe` | Sysmon (endpoint) | Fig. 5 |
| Q4 | Linux account created | `ilovedavidverve` | osquery (endpoint) | Fig. 6 |
| Q5 | Windows account created | `svcvnc` | Win Security (identity) | Fig. 7 |
| Q6 | Groups added to | `administrators,user` | Win Security (privilege) | Fig. 8 |
| Q7 | PID listening on port 1337 | `14356` | osquery (network/endpoint) | Fig. 9 |
| Q8 | MD5 hash | `586ef56f4d8963dd546163ac31c865d7` | Sysmon (endpoint) | Fig. 10 |

---
