import "hash"
// Salamander CTI  //  https://salacti.com
// Security Advisory - Action Required - July 2026 Security Update

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
