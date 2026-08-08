import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-62836: Improper restriction of communication channel to intended endpoints in Azure SQL Managed I

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
