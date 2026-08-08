import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-71944: D-Link DWR-M961 devices with hardware version C1 and firmware version before 1.1.5_C1_2026

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
