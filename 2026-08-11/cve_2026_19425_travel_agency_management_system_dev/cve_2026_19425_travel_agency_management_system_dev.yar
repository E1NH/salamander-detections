import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-19425: Travel Agency Management System developed by Win Men Intermational has a SQL Injection vul

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
