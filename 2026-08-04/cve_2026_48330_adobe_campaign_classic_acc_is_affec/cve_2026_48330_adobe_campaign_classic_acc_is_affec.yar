import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-48330: Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Elements

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
