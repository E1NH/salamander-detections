import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-67342: ArcadeDB versions before 26.7.2 contain an authorization bypass vulnerability in HTTP hand

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
