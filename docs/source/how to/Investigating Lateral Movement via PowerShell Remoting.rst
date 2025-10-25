Investigating Lateral Movement via PowerShell Remoting
======================================================

Objective
---------

This investigation aims to detect, analyze, and respond to adversary
activity leveraging PowerShell Remoting (WinRM/WSMan) for lateral
movement. Attackers use this technique to execute commands (e.g.,
launching binaries like calc.exe) on remote systems, often after
credential theft. Detecting this behavior is essential to prevent
adversaries from expanding control within the environment.

Prerequisites
-------------

**Data Sources**

- **Windows Event Logs**

  - Security: 4624 (Successful Logon), 4625 (Failed Logon), 4648 (Logon
    using explicit credentials)

  - PowerShell Operational: 4103 (Module Logging), 4104 (Script Block
    Logging)

  - Microsoft-Windows-WinRM/Operational: 6 (Session creation), 11 (WSMan
    shell creation)

- **Sysmon**: 1 (Process creation)

- **EDR / Endpoint Telemetry**: Process and command-line execution

- **Network Monitoring**: Traffic on WinRM ports (TCP 5985/5986)

**Knowledge Base**

- PowerShell commands: New-PSSession, Enter-PSSession, Invoke-Command

- MITRE ATT&CK Techniques: T1028 (Windows Remote Management), T1569.002
  (PowerShell Remoting)

Technical Overview
------------------

PowerShell Remoting enables remote command execution via WinRM.
Adversaries exploit it to:

- Execute binaries or scripts remotely (e.g., Invoke-Command calc.exe)

- Move laterally across systems using stolen credentials

- Bypass restrictions by enabling remoting on a target
  (Enable-PSRemoting -Force)

**Artifacts of Execution**

- **Initiator (Attacker)**

  - Event 4648 (explicit credential use)

  - WinRM Operational Event 6 (session creation with Activity ID and
    ProcessID)

- **Target (Victim)**

  - Event 4624 (successful network logon, Logon Type 3)

  - WinRM Operational Event 11 (WSMan shell creation)

- **Network**

  - Connections over TCP 5985/5986 between hosts not normally involved
    in remote management

Steps to Investigate
--------------------

**Step 1: Detect Remote Session Initiation**

- **Red (Attacker)**

  - Enable remoting: **Enable-PSRemoting -Force**

  - Establish sessions: **New-PSSession, Enter-PSSession,
    Invoke-Command**

.. figure:: /_static/image1.png
   :align: center


- **Blue (Defender)**

  - Review WinRM configuration changes and enablement

  - Detect changes in WSMan client settings (especially TrustedHosts)

    - Check WinRM logs: Event 6: Session creation

|A screenshot of a computer AI-generated content may be incorrect.|

- Event 11: WSMan shell creation (remote PowerShell session initiated)

.. figure:: /docs/media/media/image2.png
   :align: center

**Step 2: Correlate Authentication Events**

**Red (Attacker)**

- Authenticate using stolen credentials with New-PSSession -Credential

- May trigger explicit credential prompts

**Blue (Defender)**

- Initiator: Event 4648 (explicit credentials)

- Target: Event 4624 (Logon Type 3)

- Validate account permissions and legitimacy of source/destination
  hosts

|A white background with black text AI-generated content may be
incorrect.|

**Step 3: Review Remote Execution**

**Red (Attacker)**

- Execute payloads (e.g., calc.exe, credential dumpers)

- Use Invoke-Command for remote execution

- Obfuscate activity with -Encoded Command or Base64 payloads

**Blue (Defender)**

- PowerShell Logs:

  - 4103 (Module Logging)

  - 4104 (Script Block Logging) look for encoded/obfuscated commands

- Correlate with Sysmon Event 1 (process creation)

  - Parent: C:\\Windows\\system32\\wsmprovhost.exe -Embedding

  - Process name: powershell.exe

|A diagram of a computer system AI-generated content may be incorrect.|

|Detecting Offensive PowerShell Attack Tools – Active Directory & Azure
AD/Entra ID Security|

|A close up of a white background AI-generated content may be
incorrect.|

|image3|

**Step 4: Identify Malicious Behavior**

**Red (Attacker)**

- Create scheduled tasks or services for persistence

- Download external payloads (IEX(New-Object
  Net.WebClient).DownloadString())

- Modify registry keys for persistence

**Blue (Defender)**

- Monitor scheduled task creation (4698)

- Detect new/unusual services

- Inspect suspicious registry changes (4657)

- Check for outbound PowerShell web requests

|Windows registry subkey creation not generating logs (Windows event ID
4657) - Server Fault|

|Well that escalated quickly: How a red team went from domain user to
kernel memory \| Expel|

|image4|

**Step 5: Validate with Network Data**

- **Red (Attacker):** Use WinRM over TCP 5985 (HTTP) or 5986 (HTTPS) for
  lateral connections.

- **Blue (Defender):** Review internal traffic on ports 5985/5986.
  Confirm whether the connections originate from legitimate admin hosts
  or suspicious user endpoints.

|image5|

.. |A screen shot of a computer AI-generated content may be incorrect.| image:: C:\Users\AK\Documents\kb\output\media/media/image2.png
   :width: 6.26806in
   :height: 1.02153in
.. |A screenshot of a computer AI-generated content may be incorrect.| image:: C:\Users\AK\Documents\kb\output\media/media/image3.jpeg
   :width: 5.88819in
   :height: 2in
.. |image2| image:: C:\Users\AK\Documents\kb\output\media/media/image4.jpeg
   :width: 6.26806in
   :height: 1.92361in
.. |A white background with black text AI-generated content may be incorrect.| image:: C:\Users\AK\Documents\kb\output\media/media/image5.jpeg
   :width: 6.26806in
   :height: 0.92569in
.. |A diagram of a computer system AI-generated content may be incorrect.| image:: C:\Users\AK\Documents\kb\output\media/media/image6.png
   :width: 6.26806in
   :height: 4.75625in
.. |Detecting Offensive PowerShell Attack Tools – Active Directory & Azure AD/Entra ID Security| image:: C:\Users\AK\Documents\kb\output\media/media/image7.png
   :width: 4.26942in
   :height: 3.45149in
.. |A close up of a white background AI-generated content may be incorrect.| image:: C:\Users\AK\Documents\kb\output\media/media/image8.jpeg
   :width: 6.26806in
   :height: 1.02431in
.. |image3| image:: C:\Users\AK\Documents\kb\output\media/media/image9.png
   :width: 6.26806in
   :height: 4.21528in
.. |Windows registry subkey creation not generating logs (Windows event ID 4657) - Server Fault| image:: C:\Users\AK\Documents\kb\output\media/media/image10.png
   :width: 5.58878in
   :height: 6.04574in
.. |Well that escalated quickly: How a red team went from domain user to kernel memory \| Expel| image:: C:\Users\AK\Documents\kb\output\media/media/image11.png
   :width: 6.26806in
   :height: 4.13681in
.. |image4| image:: C:\Users\AK\Documents\kb\output\media/media/image12.png
   :width: 6.26806in
   :height: 0.91042in
.. |image5| image:: C:\Users\AK\Documents\kb\output\media/media/image13.png
   :width: 4.92336in
   :height: 2.09622in













