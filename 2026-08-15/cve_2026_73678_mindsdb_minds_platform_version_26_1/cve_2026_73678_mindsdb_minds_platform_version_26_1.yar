import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-73678: MindsDB Minds Platform version 26.1.0 and earlier contains an unauthenticated remote code 

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
