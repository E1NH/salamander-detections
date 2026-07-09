import "hash"
// Salamander CTI  //  https://salacti.com
// Understanding Langflow CVE-2026-55255, and why higher CVSS vulnerabilities aren't always the most exploited

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "VShell"
  condition:
    false  // no file hashes in this brief
}
