DFIR Investigation: XLMRat Malware Analysis
CyberDefenders Lab | Network Forensics | Malware Analysis







1. Overview

This report documents the investigation of a malware delivery and execution scenario from the XLMRat lab on CyberDefenders.

The investigation focused on analyzing network traffic, identifying the initial malware download, examining malicious scripts, recovering payload information, validating file hashes, and identifying the malware family.

The scenario also involved stealthy execution through a Windows Living-off-the-Land Binary (LOLBin) and techniques associated with reflective code loading.

Platform: CyberDefenders
Lab: XLMRat
Category: Network Forensics
Investigation type: Network traffic analysis and malware triage

Investigation objectives
Identify the URL used to download the first malware stage.
Determine the hosting provider associated with the attack infrastructure.
Follow HTTP traffic to identify and recover malware artifacts.
Deobfuscate the relevant payload and calculate its SHA256 hash.
Identify the malware family and PE compilation timestamp.
Investigate the LOLBin used for stealthy execution.
Identify files dropped by the malicious script.
Map relevant attacker techniques to MITRE ATT&CK.
2. Tools and Environment
Tool	Purpose
Wireshark	PCAP inspection, HTTP filtering, and TCP stream analysis
CyberChef	Payload decoding and deobfuscation
VirusTotal	File hash analysis, malware identification, and PE metadata inspection
Python 3	Potential artifact parsing and analysis automation
MITRE ATT&CK	Classification of observed attacker techniques

The investigation was performed using artifacts supplied by the lab. The analysis was conducted for educational and defensive purposes.

3. Investigation Methodology

The investigation followed a sequential workflow:

Inspect the PCAP file and identify HTTP requests originating from the victim.
Extract the URL used to retrieve the first malware stage.
Investigate the associated IP address and hosting provider.
Follow the relevant HTTP/TCP stream to inspect the downloaded content.
Examine and deobfuscate the malicious script and identify its payloads.
Calculate and validate the malware executable's SHA256 hash.
Use VirusTotal to examine the executable's malware classification and PE metadata.
Identify the LOLBin and files referenced by the malicious script.
Map the observed behavior to relevant MITRE ATT&CK techniques.
4. Investigation and Findings
4.1. Initial Malware Delivery — HTTP Traffic Analysis

Objective: Identify the URL from which the first malware stage was downloaded.

I opened the provided PCAP in Wireshark and filtered the traffic to focus on HTTP communications. Following the lab's investigative hints, I examined GET requests originating from the victim host.

The relevant request revealed a resource hosted on a remote IP address. Although the downloaded file used a .jpg extension, its extension alone was not sufficient to establish that it contained a legitimate image.

Finding:

First-stage download URL: http://45.126.209.4:222/mdm.jpg
Destination IP: 45.126.209.4
Protocol: HTTP
Requested resource: mdm.jpg

Evidence — Initial HTTP Request

![Wireshark HTTP GET Request](screenshots/q1-http-request.png)




Figure 1 — HTTP traffic revealing the first-stage malware download URL.

Analytical note: The request establishes the download location observed in the captured traffic. The filename extension should not be treated as proof of the downloaded file's actual format.

4.2. Hosting Infrastructure Attribution

Objective: Identify the hosting provider associated with the IP address.

After identifying the destination IP, I investigated its associated hosting infrastructure to determine the provider reported by the lab.

Finding:

IP address: 45.126.209.4
Hosting provider: reliableSite.net

Evidence — Hosting Provider Identification

![Hosting Provider](screenshots/q2-hosting-provider.png)




Figure 2 — Hosting provider associated with the malware delivery IP.

Analytical note: Infrastructure attribution helps document where the observed payload was hosted. A hosting provider's association with an IP address does not, by itself, establish that the provider knowingly participated in malicious activity.

4.3. HTTP Stream Analysis and Payload Identification

Objective: Inspect the downloaded content and identify the malware payload.

I followed the relevant HTTP/TCP stream in Wireshark to examine the data transferred by the server. The investigation revealed that the resource delivered under the .jpg filename was not a conventional image.

This reinforced the importance of inspecting the contents of transferred files instead of relying exclusively on filenames or extensions.

The recovered content was then examined as part of the malicious script and payload analysis.

Evidence — TCP Stream Inspection

![TCP Stream Analysis](screenshots/tcp-stream-analysis.png)




Figure 3 — TCP stream inspection of the content associated with the malware delivery chain.

Key observation: HTTP stream analysis provided the context needed to connect the initial download with the subsequent script and payload investigation.

4.4. Script Deobfuscation and Payload Analysis

Objective: Examine the malicious content and recover information about the executable payload.

I used CyberChef to decode the relevant obfuscated content and inspect the resulting data. The analysis helped identify the malware executable and obtain its SHA256 hash.

Recovered executable SHA256:

1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798

Evidence — CyberChef Decoding

![CyberChef Payload Analysis](screenshots/cyberchef-decoded-sha256.png)




Figure 4 — Decoded payload analysis and SHA256 identification in CyberChef.

Analytical note: The hash provides a stable identifier for the recovered executable. It can be used to correlate the artifact with external threat intelligence and malware analysis results.

4.5. File Hash Validation and Malware Family Identification

Objective: Validate the executable's SHA256 and identify its malware family.

I submitted the executable's SHA256 identifier to VirusTotal to review the available file intelligence and detection results.

The lab identified the malware family as AsyncRAT, based on Alibaba's classification.

Findings:

Attribute	Result
Malware family	AsyncRAT
Classification source requested by the lab	Alibaba
SHA256	1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798

Evidence — VirusTotal Hash Analysis

![VirusTotal SHA256](screenshots/virustotal-sha256.png)




Figure 5 — VirusTotal artifact identification using the executable's SHA256.

Evidence — Malware Family Classification

![AsyncRAT Classification](screenshots/virustotal-asyncrat-family.png)




Figure 6 — Malware family classification identifying AsyncRAT.

Analytical note: Malware family attribution is based on the classification reported by the lab. In an independent investigation, it is good practice to compare multiple detection engines, behavioral evidence, and relevant malware characteristics rather than relying on a single vendor label.

4.6. PE Compilation Timestamp

Objective: Extract the executable's PE header compilation timestamp.

I examined the executable's metadata through VirusTotal to identify the PE compilation timestamp reported for the artifact.

Finding:

PE compilation timestamp: 2023-10-30 15:08

Evidence — PE Metadata

![PE Compilation Timestamp](screenshots/virustotal-pe-timestamp.png)




Figure 7 — PE metadata displaying the reported compilation timestamp.

Analytical note: A PE compilation timestamp is a useful metadata artifact, but it should not automatically be interpreted as the actual date and time the malware was created or deployed. PE timestamps can be manipulated, and the reported time may require timezone clarification.

4.7. LOLBin Identification and Stealthy Execution

Objective: Identify the Windows binary leveraged by the malicious script for stealthy execution.

The lab's script analysis identified the following executable:

C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe

Finding:

LOLBin: RegSvcs.exe
Full path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe

RegSvcs.exe is a legitimate Microsoft .NET Framework utility associated with registering serviced components. Like other legitimate Windows binaries, it can be abused in malicious execution chains.

The security significance depends on how the binary is invoked, which arguments are supplied, and whether its execution matches expected administrative activity.

Evidence: The executable path was identified through analysis of the malicious script and the lab's findings.

Note: A dedicated screenshot of this finding can be added here if available.

4.8. Files Dropped by the Malicious Script

Objective: Identify the filenames referenced as files dropped by the script.

The lab identified the following files:

conted.ps1
conted.bat
conted.vbs

Finding: The script was designed to drop three files associated with the execution chain.

The extensions suggest different script or command-execution formats:

File	Format	Investigation relevance
conted.ps1	PowerShell script	Script execution and payload delivery
conted.bat	Batch file	Windows command execution
conted.vbs	VBScript	Windows scripting and execution orchestration

These are format-based interpretations, not proof of each file's exact role. Establishing their behavior independently would require inspecting their contents and execution context.

Evidence: The filenames were recovered during the lab's malicious script analysis.

Note: Add a screenshot of the script's file-writing or file-dropping instructions here if available.

5. MITRE ATT&CK Mapping

The following techniques are relevant to the behaviors investigated in this lab. The mapping distinguishes behaviors supported by the reported findings from techniques that require additional confirmation.

Technique	ID	Relevance
PowerShell	T1059.001	Relevant to the identified PowerShell script and its execution context
System Binary Proxy Execution: Regsvcs/Regasm	T1218.009	Relevant to the identified RegSvcs.exe LOLBin
Reflective Code Loading	T1620	Relevant to the lab's focus on reflective code loading; requires behavioral or script-level evidence to confirm the precise implementation
Ingress Tool Transfer	T1105	Relevant to the observed download of a malware stage over HTTP

Interpretation: The observed download supports investigation of tool transfer, while the identified PowerShell script and RegSvcs.exe provide context for script execution and potential proxy execution. Reflective code loading should be treated as a technique to validate against the script or payload behavior, rather than inferred solely from the use of a LOLBin.

Reference: MITRE ATT&CK

6. Consolidated Findings
Question	Finding
First-stage malware URL	http://45.126.209.4:222/mdm.jpg
Hosting provider	reliableSite.net
Malware executable SHA256	1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798
Malware family (Alibaba)	AsyncRAT
PE compilation timestamp	2023-10-30 15:08
LOLBin full path	C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
Files dropped by the script	conted.ps1, conted.bat, conted.vbs
7. Defensive Implications

The investigation illustrates several useful defensive practices:

Inspect network payloads, not just filenames. A .jpg extension does not establish that a resource contains image data.
Correlate network and host artifacts. HTTP requests, downloaded files, script contents, and PE metadata provide a more complete picture when analyzed together.
Monitor suspicious LOLBin usage. Unexpected execution of RegSvcs.exe, unusual command-line arguments, and suspicious parent-child process relationships can provide valuable detection opportunities.
Track artifacts using cryptographic hashes. SHA256 enables consistent identification and correlation across analysis tools and threat intelligence sources.
Treat malware attribution as an evidence-based conclusion. Vendor classifications are valuable indicators but should be corroborated when possible.
Preserve the investigation trail. Screenshots, extracted artifacts, timestamps, and documented conclusions improve reproducibility and reporting quality.
8. Conclusion

The XLMRat lab provided practical experience in network forensics and malware triage, from identifying an initial HTTP download to analyzing a recovered payload and correlating its hash with external malware intelligence.

The investigation identified the first-stage download URL, the reported hosting provider, the AsyncRAT family classification, the PE compilation timestamp, the use of RegSvcs.exe, and three filenames associated with the malicious script.

The most important lesson was the value of correlating multiple evidence sources. Network traffic established the delivery context, payload analysis supported artifact identification, and external intelligence provided additional classification and metadata.

This exercise strengthened my understanding of PCAP analysis, HTTP stream inspection, script deobfuscation, malware artifact identification, hash-based investigation, and MITRE ATT&CK mapping.

9. Lab Information and Disclaimer
Platform: CyberDefenders
Challenge: XLMRat
Category: Network Forensics
Purpose: Educational blue-team investigation and defensive malware analysis

This report documents findings from an authorized training lab. The IP addresses, filenames, hashes, and malware indicators are included for analysis and educational purposes. The findings should not be interpreted as independent attribution of the activity to a particular individual or organization.

Lab reference: CyberDefenders — XLMRat

Author: Daniel Widal
Focus: DFIR | Network Forensics | Malware Analysis | Blue Team
