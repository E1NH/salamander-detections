import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-63106: ReadyEcommerce before 4.5.2 contains an unauthenticated SQL injection vulnerability in the

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
