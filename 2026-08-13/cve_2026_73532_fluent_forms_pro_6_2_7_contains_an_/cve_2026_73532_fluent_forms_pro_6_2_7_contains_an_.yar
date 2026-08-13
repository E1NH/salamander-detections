import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-73532: Fluent Forms Pro 6.2.7 contains an embedded malicious code vulnerability introduced via a 

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
