import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-86148: A security flaw has been discovered in Tenda CP3 27.5.57.101

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
