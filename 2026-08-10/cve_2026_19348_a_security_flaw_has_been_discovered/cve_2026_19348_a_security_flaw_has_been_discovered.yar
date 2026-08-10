import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-19348: A security flaw has been discovered in Shenzhen Aitemi M300 Wi-Fi Repeater r0-ea7890a

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
