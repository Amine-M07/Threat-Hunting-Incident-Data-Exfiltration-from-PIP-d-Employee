# 🎯 Suspected Data Exfiltration from PIP'd Employee
<img width="1024" height="572" alt="b6ffa07e-193d-4101-8ffd-48d812d5eada" src="https://github.com/user-attachments/assets/b99fd364-bc0c-4e1b-a779-29719bfe7199" />

## Incident Investigation Report

---

## 📚 Scenario

An employee, **John Doe**, working in a sensitive department, was recently placed on a **Performance Improvement Plan (PIP)**. After reacting negatively to the news, management raised concerns that John may attempt to steal proprietary information before leaving the company. John is a local administrator on his corporate device and is not restricted in the applications he can run.

The task was to investigate John's activity on his device using **Microsoft Defender for Endpoint (MDE)** to determine whether any data staging, compression, or exfiltration was taking place.

**Hypothesis:** John may attempt to archive or compress sensitive company data and transmit it to an external, personally-controlled destination (e.g., a private cloud drive) prior to his departure.

---

## 📊 Incident Summary and Findings

**Goal:** Gather relevant data from process, file, and network logs to confirm or rule out data exfiltration.

**Activity:** Ensure data is available from all key sources for analysis. Ensure the relevant tables contain recent logs for the target device:

- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

---

### Timeline Overview

#### 1. 🔍 Archive Activity Discovery

**Observed Behavior:** A search of `DeviceFileEvents` for archive-related file activity on the target host (`wind11-mo-test` — logged by MDE with a truncated device name, consistent with `windows-target-`) returned a pattern of files being zipped and moved into what appeared to be a routine "backup" folder — but the volume and naming warranted a closer look.

**Detection Query (KQL):**

```kql
DeviceFileEvents
| where DeviceName contains "wind11-mo-test"
| where FileName endswith "zip"
| order by Timestamp desc
```

<img width="859" height="285" alt="image" src="https://github.com/user-attachments/assets/e5eff287-cef6-4094-9708-83ba4785b655" />


---

#### 2. ⚙️ Process Correlation

**Observed Behavior:** Pivoting on the timestamp of a discovered archive-creation event, I searched `DeviceProcessEvents` for activity within a ±2 minute window on the same host. This revealed a PowerShell process that silently installed 7-Zip and then invoked it to compress employee data into an archive — activity that was not part of any approved backup or IT process.

**Detection Query (KQL):**

```kql
let VMName = "wind11-mo-test";
let specificTime = datetime(2026-05-20T06:20:56.0480175Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, AccountName, ActionType, FileName, ProcessCommandLine
```

<img width="748" height="357" alt="image" src="https://github.com/user-attachments/assets/69890284-8f89-4446-b71b-f58ecbd85131" />


---

#### 3. 🌐 Network Correlation

**Observed Behavior:** Using the same timestamp, I pivoted to `DeviceNetworkEvents` to check for outbound activity tied to the process. A PowerShell process executed the script `C:\programdata\exfiltratedata.ps1` with `-ExecutionPolicy Bypass`, which established multiple successful outbound HTTPS (port 443) connections in rapid succession to two external IP addresses — `20.60.181.193` and `20.60.133.132` — from the same process, under user `amine`.

**Detection Query (KQL):**

```kql
let VMName = "wind11-mo-test";
let specificTime = datetime(2026-05-20T06:20:56.0480175Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

<img width="756" height="274" alt="image" src="https://github.com/user-attachments/assets/e5fa8c7a-e51e-4985-a3e1-84eb861f37c9" />


Reviewing the script itself confirmed that `exfiltratedata.ps1` generated a CSV file containing simulated sensitive employee information, compressed it into a ZIP archive using the freshly-installed 7-Zip, and uploaded the archive to external **Azure Blob Storage** over HTTPS — matching the outbound connections observed in the network logs.

---

#### 4. 📝 Response

- Immediately isolated the affected host (`wind11-mo-test`) from the network to prevent further outbound communication or exfiltration.
- Terminated the suspicious `powershell.exe` process associated with `exfiltratedata.ps1`.
- Removed `exfiltratedata.ps1` and related artifacts from `C:\ProgramData`.
- Identified and blocked the external IP addresses `20.60.181.193` and `20.60.133.132`.
- Reviewed additional endpoints for similar PowerShell activity and outbound patterns.
- Reviewed PowerShell execution policies and logging configuration to improve future detection.
- Shared findings with management, confirming the presence of scripted, automated data staging and exfiltration consistent with the initial hypothesis. Awaiting further HR/legal guidance.


---

## 🗺️ MITRE ATT&CK Techniques for Incident Notes

| **Tactic** | **Technique** | **ID** | **Description** |
|---|---|---|---|
| Execution | [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) | T1059.001 | `exfiltratedata.ps1` was executed via `powershell.exe` with `-ExecutionPolicy Bypass` to silently install 7-Zip and generate/compress the target CSV data. |
| Collection | [Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/) | T1560.001 | Sensitive employee data was compressed into a ZIP archive using a covertly installed 7-Zip instance prior to exfiltration. |
| Exfiltration | [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | T1041 | The archive was transmitted out over the same PowerShell-initiated HTTPS session used to stage and control the activity. |
| Exfiltration | [Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/) | T1567 | The compressed archive was uploaded to external Azure Blob Storage endpoints (`20.60.181.193`, `20.60.133.132`) over HTTPS (port 443). |

---

## 🛠️ Mitigation & Improvement

The affected host should remain isolated until fully re-imaged, the malicious PowerShell script and any dropped 7-Zip binaries removed, and outbound connections to unauthorized cloud storage services restricted at the network egress layer.

PowerShell execution should be restricted through constrained language mode and stricter execution policies so scripts cannot run with `-ExecutionPolicy Bypass`. Application control should prevent unauthorized installation of archive utilities such as 7-Zip on endpoints where it isn't already approved.

For future hunts, correlating PowerShell script-block logging with network egress events earlier in the pipeline would shorten detection time. Establishing a baseline for normal outbound traffic per host/user and alerting on connections to unfamiliar external destinations (especially cloud storage ranges) would further strengthen detection of this pattern.

---

## Created By

- **Author Name:** Amine Mouammine
- **Author Contact:** [linkedin.com/in/aminemouammine](https://www.linkedin.com/in/aminemouammine/)
- **Date:** Jul 2026

## Validated By

- **Reviewer Name:** Josh Madakor
- **Reviewer Contact:** [linkedin.com/in/joshmadakor](https://www.linkedin.com/in/joshmadakor/)
- **Validation Date:** Jul 2026

---

## Revision History

| **Version** | **Changes** | **Date** | **Modified By** |
|---|---|---|---|
| 1.0 | Initial draft | Jul 2026 | Amine Mouammine |
