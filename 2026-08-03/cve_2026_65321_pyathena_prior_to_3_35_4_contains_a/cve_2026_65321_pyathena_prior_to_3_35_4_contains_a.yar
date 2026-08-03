import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-65321: PyAthena prior to 3.35.4 contains a sql injection vulnerability that allows unauthenticate

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
