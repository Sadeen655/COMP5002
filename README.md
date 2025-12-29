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
