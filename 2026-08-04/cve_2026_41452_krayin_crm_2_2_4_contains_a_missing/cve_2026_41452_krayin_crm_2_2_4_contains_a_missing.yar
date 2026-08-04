import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-41452: Krayin CRM 2.2.4 contains a missing authentication vulnerability in the installer middlewa

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
