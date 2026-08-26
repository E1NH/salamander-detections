import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-16286: Unrestricted upload of file with dangerous type vulnerability in TRtek Technological Produ

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
