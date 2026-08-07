import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-53984: Ground Station prior to 0.6.0 contains an unauthenticated database-destruction and arbitra

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
