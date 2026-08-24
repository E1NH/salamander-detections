import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-78167: A weakness has been identified in EFM ipTIME T16000M 14.20.2

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
