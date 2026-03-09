Investigating Lateral Movement via PsExec SysInternals Tool
===========================================================

Objective 
----------

To investigate and detect lateral movement attempts using PsExec, a
legitimate Sysinternals tool often abused by attackers. PsExec allows
remote execution of commands or binaries on other systems without
requiring physical access. While useful for administrators, adversaries
frequently use it for post-exploitation movement within networks.

Prerequisites
-------------

To effectively investigate, the following are essential

1. Logging Enabled

   - Windows Security Logs

   - Sysmon Logs

2. Detection Data Sources

   - Remote logon attempts

   - File/Process creation and command-line arguments

   - Network Behavior

3. EDR/XDR SIEM Alerts

   - Alerts for lateral movement tools usages (e.g., PsExec, RDP, SSH,
     etc...)

   - Detection of suspicious service creation or modification events

Technical Overview
------------------

PSExec is a legitimate tool developed by Sysinternals Suite that allows
administrators to execute processes on other systems remotely. This tool
is frequently exploited for lateral movement by Threat Actors.

Suspicious PsExec Usage Patterns:

1. Establishes an SMB network connection to a target system using
   administrator credentials.

2. Create and start a windows service remotely and execute specified
   commands under that service (PsExec copies itself to the target
   machine’s ADMIN$ share, typically named PSEXESVC.exe).

|image1|

In the above figure, a remote code execution from Host A to Host B for
lateral movement. On Host A, threat actor executed this command:
“\ **psexec.exe**\ *\\\\\ *\ **hostB -accepteula -d -c
C:\\MalwareFolder\\malware.exe”** on Host A to copy and execute
**Malware.exe** on Host B. With administrative privileges, PsExec
creates **psexesvc.exe** Host B via the ADMIN$ share, install it as a
service and then executes the malicious binary remotely.

Steps to Investigate
--------------------

**Step 1: Detect Initial Activity**

- Look for Event ID **4688** (process creation) with **PsExec.exe**

- Look for Event ID **4697** (new service was installed/created) with
  the name **PSEXECSVC** or similar.

- Look for Event ID **4624** (successful logon) on the target system.
  PsExec create a new logon session, usually a **Logon Type 3**
  (Network), which can be an indicator of remote activity.

|image2|

**Step 2: Monitor Windows Event Logs and Sysmon Logs**

- Use Windows Event IDs and Sysmon Logs relevant to investigation steps:

  - Event ID **7045** - Service Installed/created

  - Event ID **1** - Process Creation (cmd.exe, posershell.exe spawned
    by PsExec)

  - Event ID **3** - Network Connections (SMB traffic to \\\\ADMIN$)

Source Machine Event Logs

- Most **PsExec** artifacts are logged on the target machine.

- Event ID **4688** records execution of **psexec.exe**.

- Check details such as: Process name, Process path, Parent process and
  Command line.

Target Machine Event Logs

- Event ID **4624:** Successful authentication to the target system
  (e.g., ADMIN$ share).

- Event IDs **5140** and **5145:** Track accessed/mapped shared folders
  and transferred files.

- Event IDs **7045** and **4697**: Check the new service creation.

  - Event ID 4697: creation of a new service

  - Service name is PSEXESVC

    - Installed by User: pbeesly

    - Running Account: LocalSystem

    - Possible Indication: Legitimate administrative activity or remote
      management using PsExec.

  - Executes the binary: %SystemRoot%\\PSEXESVC.exe

  - Service start type value is 3 (Manual start)

  - This mean the PSEXESVC service will only be executed.

|image3|

**Step 3: Check Two events 4697 and 4688**

- Event ID **4697:** Records creation of a new service named
  **PSEXESVC.**

- Executes **%SystemRoot%\\PSEXESVC.exe.**

- Event ID **4688:** Records execution of **PSEXESVC.exe** (spawned by
  **services.exe** (parent process))

|A screenshot of a computer AI-generated content may be incorrect.|

**Step 4: Investigating Suspicious Access**

- **Objective:** Identify remotely executed binaries and code by PsExec.

- **Method:** Use **Process ID** of PSEXESVC.exe to track spawned
  processes.

- **Finding:** Python.exe running from **C:\\Windows\\Temp** was spawned
  by PSEXESVC.exe.

|image4|

**Step 5: Investigating Activity after successful attempted**

- Detection Guidance

  - Check for PsExec execution by non-admin users

  - Monitor for activity outside normal office hours

  - Check on execution and spawned process by PSEXESVC.exe on a remote
    system

- PsExec Usages

  - Legitimate: used by system/windows administrator

  - Malicious: abused by threat actor for Lateral Movement

.. |image1| image:: C:\Users\AK\Documents\kb\output\media\psexc/media/image1.png
   :width: 6.26806in
   :height: 2.23958in
.. |image2| image:: C:\Users\AK\Documents\kb\output\media\psexc/media/image2.png
   :width: 4.16531in
   :height: 3.38126in
.. |image3| image:: C:\Users\AK\Documents\kb\output\media\psexc/media/image3.png
   :width: 6.26806in
   :height: 2.61458in
.. |A screenshot of a computer AI-generated content may be incorrect.| image:: C:\Users\AK\Documents\kb\output\media\psexc/media/image4.png
   :width: 5.1986in
   :height: 3.50413in
.. |image4| image:: C:\Users\AK\Documents\kb\output\media\psexc/media/image5.png
   :width: 5.60815in
   :height: 3.75285in
