import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-67341: ArcadeDB versions before 26.7.2 fail to enforce scripting authorization checks on the SQL 

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
