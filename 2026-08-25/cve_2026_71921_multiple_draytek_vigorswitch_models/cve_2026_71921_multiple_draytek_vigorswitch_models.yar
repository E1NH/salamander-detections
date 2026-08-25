import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-71921: Multiple DrayTek VigorSwitch models contain a pre-authentication command injection vulnera

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
