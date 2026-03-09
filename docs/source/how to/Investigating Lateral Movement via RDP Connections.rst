Investigating Lateral Movement via RDP Connections
==================================================

Objective
---------

This guide provides instructions for detecting and investigating lateral
movement within a Windows environment through Remote Desktop Protocol
(RDP). Attackers often abuse RDP to move between systems after obtaining
valid credentials, allowing them to expand their access and escalate
privileges.

Prerequisites
-------------

- Administrator access to suspected hosts or access to SIEM

- Access to Windows Security Event Logs (from target and source systems)

- Optional: EDR, Sysmon, or centralized monitoring tools for enhanced
  visibility

Technical Overview
------------------

Remote Desktop Protocol (RDP) allows users to remotely connect to
another Windows system. While RDP is commonly used for legitimate
administration, attackers use it for lateral movement once credentials
are compromised. Monitoring RDP logons can help detect unauthorized
access and potential lateral movement.

**Key Event IDs to Look For:**

- **4688** - Process creation (e.g., mstsc.exe on source, rdpclip.exe on
  target)

- **4624** - Successful logon (logon type 10 = RemoteInteractive via
  RDP)

- **4625** - Failed logon attempt

- **4672** - Special logon (admin user login)

- **4634 / 4647** - Session logoff events

- **4778 / 4779** - RDP session reconnect/disconnect

.. figure:: /_static/RDP/image1.png 
   :align: center  
   :class: bottom-space

Steps to Investigate
--------------------

**Step 1: Identify RDP Logon Events on Target Machine**

- Search for Event ID 4624 with Logon Type 10 (RemoteInteractive).

- Look for unusual logon times, systems, or accounts not typically used
  for RDP.

- Verify whether the source IP address belongs to internal
  infrastructure or an external network.

.. figure:: /_static/RDP/image2.png 
   :align: center  
   :class: bottom-space

**Step 2: Investigate Failed Logon Attempts**

- Review Event ID 4625 for failed RDP logon attempts.

- Identify repeated failures followed by a successful logon, which may
  suggest brute-force or password spraying.

- Pay attention to accounts with multiple failures across different
  hosts.

**Step 3: Investigate Logon Attempts on Source Machine**

- Look for Event ID 4688 showing execution of mstsc.exe (RDP client).

- Correlate with the user account running mstsc.exe. Is it expected for
  that user?

- Multiple executions in a short timeframe may indicate scanning or
  brute forcing across hosts.

**Step 4: Correlate Source and Destination**

- Identify the **source IP** and **hostname** initiating the RDP
  connection.

- Determine whether lateral movement came from an already compromised
  internal system.

- Check firewall or network logs for RDP over external connections if
  the system is exposed.

**Step 5: Investigate Account Usage**

- Determine if the account used is privileged (e.g., domain admin,
  server admin) by correlating with Event ID 4672.

- Check for accounts accessing new or unusual systems.

- Correlate with recent privilege changes, password resets, or group
  membership modifications.

**Step 6: Investigate Activity After Logon**

- Correlate RDP logon time with process creation events (via Sysmon or
  EDR).

- Look for execution of suspicious tools (e.g., mimikatz.exe,
  psexec.exe, powershell.exe).

- Review file access, lateral movement attempts, and possible data
  exfiltration.

.. |image1| image:: C:\Users\AK\Documents\kb\output\RDP/media/image1.png
   :width: 6.26806in
   :height: 5.16111in
.. |image2| image:: C:\Users\AK\Documents\kb\output\RDP/media/image2.png
   :width: 5.02849in
   :height: 4.89304in

