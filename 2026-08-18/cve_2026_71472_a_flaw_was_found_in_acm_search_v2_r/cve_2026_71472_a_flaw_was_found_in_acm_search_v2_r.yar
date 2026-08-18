import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-71472: A flaw was found in acm-search-v2-rhel9

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
