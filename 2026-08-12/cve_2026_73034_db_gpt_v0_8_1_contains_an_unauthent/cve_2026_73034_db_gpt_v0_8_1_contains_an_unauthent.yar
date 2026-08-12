import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-73034: DB-GPT v0.8.1 contains an unauthenticated path traversal vulnerability that allows remote 

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
