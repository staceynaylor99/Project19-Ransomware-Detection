Overview

In this project, I simulated two early-stage ransomware behaviors and used Sysmon process monitoring to detect them. Instead of relying on file extension changes, this project focuses on behavior-based detection, which is more reliable against modern ransomware variants. The two behaviors I replicated were:

Backup destruction attempts using vssadmin delete shadows, and

Stealthy PowerShell execution using powershell.exe -nop -w hidden.

Both behaviors occurred before any encryption takes place, making them critical early indicators for SOC analysts and incident responders.

Behavior 1: Shadow Copy Deletion Attempt
What happened

I executed the following command, which is commonly used by ransomware to remove recovery options:

vssadmin delete shadows /all /quiet


This command attempts to delete all Volume Shadow Copies—the built-in Windows backups. Ransomware does this so the victim cannot restore files after encryption.

How I detected it

Sysmon captured this action under Event ID 1 – ProcessCreate.
Key evidence in the event:

Image: C:\Windows\System32\vssadmin.exe

CommandLine: vssadmin.exe delete shadows /all /quiet

ParentImage: PowerShell

User: My administrative account

IntegrityLevel: High

This proves that a high-integrity process attempted to wipe shadow copies.
In a real organization, this single event would be considered high severity, even if no encryption had occurred yet.

Why it's dangerous

Shadow copy deletion is one of the strongest behavioral indicators of ransomware.
Legitimate software almost never executes this command silently (/quiet).
Seeing this activity means an attacker is preparing the system for irreversible file encryption.

Behavior 2: Stealthy PowerShell Execution
What happened

I executed a hidden PowerShell launch using:

powershell.exe -nop -w hidden


This is a common technique used by malicious scripts and ransomware loaders to evade user attention and bypass basic defenses.

How I detected it

Sysmon logged this activity with rich detail under Event ID 1 – ProcessCreate:

Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine: powershell.exe -nop -w hidden

ParentImage: cmd.exe

User: My account (high integrity)

This shows a suspicious execution chain where cmd.exe spawned PowerShell with flags that disable profiles (-nop) and hide the window (-w hidden).
These flags are heavily associated with malware, fileless attacks, and ransomware staging.

Why it's dangerous

Hidden PowerShell execution indicates an attempt to run scripts without user awareness.
Attackers often use this method to:

Execute malicious payloads

Download ransomware tools

Modify registry keys

Launch encryption routines

This behavior is rarely used in normal operations.

How These Behaviors Fit Together

When these two events happen close together:

Stealthy PowerShell → used as the launcher

Shadow copy deletion → used to eliminate recovery

Potential encryption phase next

…it matches the early attack chain of multiple ransomware families (Ryuk, Conti, BlackCat, LockBit, WannaCry).

Catching these two behaviors BEFORE encryption means stopping the attack at the most critical moment.

SOC Analyst Response Recommendations

If this occurred on an enterprise endpoint, the proper response would be:

Immediately isolate the host from the network

Terminate suspicious processes (PowerShell or vssadmin)

Check for lateral movement

Search other endpoints for similar behavior

Hunt for script origins (scheduled tasks, macro documents, network shares)

Escalate to the IR team due to high likelihood of ransomware activity

Even if no encryption has occurred yet, these process events are enough to justify an emergency response.

Conclusion

This project demonstrates how to detect behavior-based ransomware indicators, rather than relying on file extensions. By using Sysmon’s process monitoring, I captured:

Shadow copy deletion attempts

Hidden PowerShell execution

Suspicious parent-child chains

These detections map directly to MITRE ATT&CK techniques:

T1490 – Inhibit System Recovery

T1059 – Command and Scripting Interpreter (PowerShell)

T1106 – Native API Execution

T1562 – Defense Evasion

This project strengthened my ability to identify ransomware before it fully activates, which is a critical skill for SOC analysts.