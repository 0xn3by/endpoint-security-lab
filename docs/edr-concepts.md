# Endpoint detection and investigation concepts

EDR collects endpoint behavior and helps analysts detect, investigate and respond. Useful evidence includes process creation, ancestry, command lines, users/tokens, file and registry changes, and process-associated network connections.

Antivirus focuses heavily on prevention and malicious-file/behavior detection. Modern antivirus and EDR capabilities overlap. A SIEM centralizes and correlates logs across systems; an EDR usually has deeper endpoint visibility and response controls. Wazuh plus Sysmon supports this lab's monitoring and investigation workflow, but does not reproduce every commercial EDR feature.

A process tree represents which process created which child. An interactive shell starting PowerShell and whoami may be expected administration; a document reader starting encoded PowerShell, followed by unknown executable creation and external traffic, increases concern. Parentage is context, not proof: parents can be spoofed and collection can be incomplete.

Windows Sysmon process GUIDs are better correlation keys than PIDs because Windows reuses PIDs. Event 1 captures process and parent context; Event 3 associates a connection with a process; Event 13 captures a registry value set. Security 4720 records account creation with actor and target identities. These sources have different fields and must not be treated as interchangeable.

Persistence is a mechanism for later execution, such as a Run key. Creating a value does not demonstrate successful logon execution. Creating a disabled standard account does not demonstrate administrator access. An encoded command is an encoding choice, not malware proof. Local port 18080 traffic is an anomaly exercise, not command-and-control evidence.

Containment limits ongoing harm, eradication removes the cause/artifacts, recovery restores trusted operation, and lessons learned improve coverage. Preserve evidence and consider service impact before containment. This repository deliberately performs no automatic isolation or destructive response.
