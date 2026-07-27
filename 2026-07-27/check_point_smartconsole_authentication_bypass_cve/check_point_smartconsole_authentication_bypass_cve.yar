import "hash"
// Salamander CTI  //  https://salacti.com
// Check Point SmartConsole Authentication Bypass (CVE-2026-16232)

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
