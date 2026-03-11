Investigating Windows Persistence via Registry Run Keys
=======================================================

Objective
---------

This guide provides instructions for detecting and investigating malware
persistence on Windows systems by monitoring modifications to Registry
Run Keys using Windows Security Event Logs.

Prerequisites
-------------

- Administrator access to the Windows system

- Access to Security Event Logs

- Optional: HELK, Sysmon, or other SIEM tools for analysis

Technical Overview
------------------

Registry Run Keys are registry entries that automatically execute
programs when a user logs in. Attackers often modify existing keys or
create new values under these keys to maintain persistence, ensuring
their malware executes even after reboot or logoff.

**Common Registry Run Keys:**

- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

- HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

- HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce

Steps to Investigate
--------------------

**Step 1: Identify Registry Run Keys**

- Check the default Run keys listed above

- Look for any unusual or unknown entries, especially pointing to
  temporary folders (C:\\Windows\\Temp) or executables with random names

.. figure::  /_static/investigating_windows_persistence_via_registry_run_keys/image1.png 
   :align: center  
   :class: bottom-space

**Step 2: Monitor Windows Event Logs**

- Use Security Event IDs relevant to registry access:

  - **4656** – Handle to object requested

  - **4657** – Registry value modified

  - **4658** – Handle to object closed

  - **4660** – Object deleted

  - **4663** – Attempted access to object

.. figure::  /_static/investigating_windows_persistence_via_registry_run_keys/image2.png 
   :align: center  
   :class: bottom-space

**Step 3: Understanding Event Log Sections**

When reviewing events, pay attention to the following sections:

- **Subject**: Provides information about the user who performed the
  action.

- **Object:** Contains details about the accessed object

- **Process Information:** Identifies the process that performed the
  action.

- **Access Request Information:** Shows the permissions used in the
  access.

**Step 4: Investigating Suspicious Access**

- Look for suspicious processes accessing these keys, such as
  powershell.exe or cmd.exe

- Look for new or modified entries pointing to suspicious executables,
  e.g., C:\\Windows\\Temp\\Malware.exe

- Review access patterns for anomalies, including unusual times (outside
  standard working hours) or repeated access.