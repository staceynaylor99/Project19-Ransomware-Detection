Overview

This project focuses on detecting early-stage ransomware behavior using Sysmon and Windows Event Logs.
Instead of relying on file extension changes, this detection is based on process behavior, which is far more reliable and aligned with real-world SOC workflows.

I simulated two behaviors commonly seen in ransomware attacks:

Backup destruction using vssadmin delete shadows /all /quiet

Stealthy PowerShell execution using powershell.exe -nop -w hidden

These actions mimic how ransomware prepares a system before encryption. Sysmon successfully captured both behaviors under Event ID 1 (ProcessCreate).

Lab Setup

Windows 10/11 Virtual Machine

Sysmon (System Monitor)

SwiftOnSecurity Sysmon configuration

PowerShell (Admin)

Event Viewer

Folder: C:\TestRansomware

Simulated Ransomware Behavior
1. Fake “Encrypted” Files Created

I generated .locked files in the TestRansomware folder to simulate ransomware activity such as file encryption.

Get-ChildItem "C:\TestRansomware" -File | ForEach-Object {
    $new = "$($_.FullName).locked"
    Copy-Item $_.FullName $new
}

2. Attempted Shadow Copy Deletion

Ransomware typically deletes backups to prevent recovery.

vssadmin delete shadows /all /quiet

3. Stealthy PowerShell Execution

Attackers frequently launch PowerShell in hidden mode to evade the user and security controls.

powershell.exe -nop -w hidden

Evidence (Screenshots)

Add these in your GitHub repository inside a Screenshots folder.

19-Ransomware-EncryptedFiles-FolderView.png

19-Ransomware-Sysmon-EventID1-VSSDelete.png

19-Ransomware-Sysmon-EventID1-HiddenPowerShell.png

19-Ransomware-SuspiciousProcessChain-Command.png

Detection Notes & Analysis
Behavior-Based Detection (Not Signature-Based)

This project focuses on behavior instead of file extension monitoring. Modern ransomware constantly changes file extensions, but their behavior remains consistent:

Destroy backups

Execute hidden scripts

Disable recovery mechanisms

Launch PowerShell silently

The behaviors I simulated map directly to real ransomware operations.

Detection 1: Shadow Copy Deletion Attempt
What Happened

Ransomware frequently deletes shadow copies before encrypting data. I simulated this by executing:

vssadmin delete shadows /all /quiet

Sysmon Detection

Sysmon logged this under Event ID 1 – ProcessCreate with detailed fields:

Image: vssadmin.exe

CommandLine: delete shadows /all /quiet

ParentImage: PowerShell

Integrity Level: High

User: staceynaylor

Why This Is High-Risk

Shadow copy deletion is one of the clearest early indications of ransomware.
Legitimate software rarely executes this command silently, and SOC teams treat this as a high-severity alert.

Detection 2: Hidden PowerShell Execution
What Happened

I launched PowerShell invisibly using:

powershell.exe -nop -w hidden

Sysmon Detection

Sysmon again captured this under Event ID 1 – ProcessCreate:

Image: powershell.exe

CommandLine: -nop -w hidden

ParentImage: cmd.exe

Execution Level: High

Why This Is Suspicious

Attackers use hidden PowerShell to:

Load ransomware payloads

Download malware

Disable security tools

Run encryption routines unnoticed

The flags used (-nop, -w hidden) are almost exclusively seen in offensive security tools or malware.

🔗 MITRE ATT&CK Mappings
Technique	Description
T1490 – Inhibit System Recovery	Deleting shadow copies to prevent recovery
T1059 – Command and Scripting Interpreter (PowerShell)	Using PowerShell for malicious activity
T1562 – Defense Evasion	Running PowerShell with hidden/no-profile flags
T1106 – Native API Execution	Using system tools like vssadmin
SOC Response Recommendations

If this occurred on a real endpoint, recommended actions would be:

Immediately isolate the host

Terminate malicious processes (PowerShell, vssadmin)

Check for persistence mechanisms

Hunt for additional indicators across the environment

Escalate to Incident Response—these behaviors strongly indicate active ransomware staging

Search for lateral movement on other hosts

Scan for encrypted files or dropped executables

These two detections alone would justify opening a high-priority incident.

Conclusion

This project demonstrates how effective behavior-based threat detection is against ransomware. By analyzing process creation events rather than file extensions, I was able to identify:

Shadow copy deletion

Hidden PowerShell execution

Suspicious parent-child process relationships

These are some of the earliest signs of a ransomware attack, and detecting them quickly can prevent encryption entirely.
This project strengthened my skills in threat hunting, Sysmon analysis, and early-stage ransomware detection.