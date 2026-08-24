import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-7808: justhtml before 1.16.0 contains multiple HTML sanitization bypass issues that can allow ac

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
