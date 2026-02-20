# lolDrivers

LOLDrivers, why kernel drivers are the new attack surface

Why Old Signed and Legitimate are a Risk
Old but legitimately signed drivers are dangerous because they provide a trusted execution path straight into the Windows kernel, where most modern security controls have no visibility. 


Once a vulnerable driver is loaded, an attacker can abuse known flaws to gain arbitrary kernel read and write access, disable security features, tamper with credential protections, and hide processes or files, all while appearing “trusted” because the driver is signed. 


This technique, commonly called BYOVD (Bring Your Own Vulnerable Driver), bypasses application control, kernel exploit mitigations, and many EDR hooks, allowing attackers to operate below the operating system’s security boundary. 


LOLDrivers.io to the Rescue
LOLDrivers is a curated, continuously maintained catalogue of  Windows drivers that have been abused, or are suitable for abuse, in real attacks. The list covers both malicious drivers and legitimate signed drivers with exploitable flaws. 


Visit LOLDrivers, its a great resource, its free, and the database of browserable drivers is awesome. 


The original goal was to embed an offline reference of the LOLDrivers dataset into the security tool I am building. Instead, I decided to release my own PowerShell implementation.

This script creates a local, offline copy of the LOLDrivers database and provides clear, colour-coded output when a match is detected.




What “Living Off the Land Drivers” actually means
Living off the land usually refers to abusing built-in system tools. LOLDrivers applies the same concept to the kernel.


Instead of dropping custom malware, attackers load a signed, trusted, but vulnerable driver and use it as a control interface into kernel memory.


Once loaded, these drivers can be used to:

Read and write arbitrary kernel memory

Kill protected security processes

Disable EDR hooks

Bypass HVCI and protected process light (PPL)

Load unsigned kernel code


The risk categories in LOLDrivers
LOLDrivers splits drivers into functional risk classes. This is important, because not all of them are malicious by design.


Vulnerable but legitimate drivers
These are signed drivers shipped by vendors that expose IOCTL handlers or memory primitives that can be abused.


They are frequently used for:

Arbitrary kernel read/write

Token manipulation

Security product termination

Callback and hook removal

These are the backbone of most BYOVD chains.


Explicitly malicious drivers
These drivers contain intentionally malicious functionality. They are often used as stealth rootkits or kernel loaders.


Typical capabilities include:

Process hiding

File hiding

Credential interception

Persistence enforcement

These drivers usually exist only to support a wider malware framework.


Dual-use operational drivers
“Dual-use” drivers are legitimate software for admins, OEMs, and hardware vendors, but dangerous in the wrong hands. These drivers are not exploits, but they expose kernel-level control surfaces that attackers can directly abuse.


Typical capabilities include:

Physical memory access

MSR and PCI configuration

Debug and hardware inspection features

When abused, they provide the same primitives as a kernel exploit, without triggering exploit detection.


Why Microsoft’s blocklist is not enough
Microsoft maintains a kernel driver blocklist, but:

It is reactive

It is incomplete

It does not cover every vulnerable version

It is often bypassed by version pinning or re-signing


What Needs to Be Done
At a minimum, organisations must start treating driver loading as a high-risk security boundary, not a background system event. If you are not monitoring driver activity, you are blind to one of the most reliable attacker techniques in use today.


The baseline controls should include:

Integrate LOLDrivers intelligence into Sysmon, using the curated driver blocklist and metadata maintained by Magicsword.io, so that known vulnerable and malicious drivers can be detected at load time.

Log every driver load event, not just failures. Silent, successful driver loads are how attackers bypass EDR and kernel protections.

Continuously compare loaded drivers against the LOLDrivers dataset, both in real time and retrospectively, so newly classified drivers can be flagged even after they have already been seen in the environment.

Alert based on abuse category, not just a hash match. A driver used for credential theft, EDR bypass, or kernel memory access represents a fundamentally different risk than a generic vulnerable driver, and should be triaged accordingly.


Finally, credit where it's due
Credit goes to the LOLDrivers project, without their work, this attack surface would remain largely undocumented, leaving defenders blind to a class of kernel-level abuse that is actively exploited. Show your support and visit their site.
