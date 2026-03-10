Investigating Lateral Movement via Windows Admin Shares
=======================================================

Objective
---------

This guide provides instructions for detecting and investigating lateral
movement attempts in Windows environments through administrative shares.
Attackers commonly leverage default shares such as C$, ADMIN$, and IPC$
to copy tools, execute commands remotely, or establish persistence once
they obtain valid credentials.

Prerequisites
-------------

- Administrator access to Windows systems or domain logs

- Access to Security Event Logs and SMB-related logs

- Optional: Sysmon, or SIEM platform for correlation

Technical Overview
------------------

Windows creates administrative shares (C$, ADMIN$, IPC$) by default for
remote administration. **C$** allows you access to the **C: drive** of
the remote machine, **ADMIN$** allows **you access to the Windows folder
of the remote machine**, and **IPC$** is a **special Windows admin
share** usually used for named pipe connections. Attackers with stolen
credentials or elevated privileges may use these shares for:

- Copying malicious executables (copy /y malware.exe
  \\\\victim\\C$\\Windows\\Temp)

- Remotely executing code using tools like PsExec, WMI, or PowerShell
  remoting

- Establishing persistence across multiple hosts in a network

The following command as an example for mapping remote systems’ shares:

net use L: \\\\<TargetIP>\\$C <Password> /USER:<Domain>\\<User>

.. _section-1:

Steps to Investigate
--------------------

**Step 1: Identify Admin Share Access**

- Review **Security Event Logs** for logon attempts:

  - **4624** – Successful logon (look for Type 3: Network logon).

  - **4625** – Failed logon (brute-force or spray attempts).

- Check if the **Logon Process** shows NtLmSsp or Kerberos and if the
  **Workstation Name** indicates remote access.

.. figure::  /_static/investigating_lateral_movement_admin_shares/image1.png 
   :align: center  
   :class: bottom-space

**Step 2: Monitor SMB and Share Access**

- **5140** – A network share object was accessed.

- **5145** – A network share object was checked to see if the client can
  access it.

- Look for accesses to C$, ADMIN$, IPC$.

.. figure::  /_static/investigating_lateral_movement_admin_shares/image2.png 
   :align: center  
   :class: bottom-space

.. figure::  /_static/investigating_lateral_movement_admin_shares/image3.png 
   :align: center  
   :class: bottom-space

**Step 3: Understanding Event Log Sections**

- **Subject**: Account name and domain of the user accessing the share.

- **Network Information**: Source IP address (attacker’s host).

- **Share Information**: Name of the accessed share
  (\\\\<hostname>\\C$).

- **Access Information**: Requested permissions (read, write, execute).

**Step 4: Investigating Suspicious Activity**

- Look for unusual accounts accessing admin shares (non-admin users
  should not).

- Review file copy activity (Sysmon Event ID 11 for file creation on
  remote hosts).

- Detect execution attempts (e.g., PsExec service creation – Event ID
  **7045** in System log).

- Correlate timestamps of logon events with file/service creation to

  trace attacker movement.
