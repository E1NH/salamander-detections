import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-71956: D-Link DWR-M961 devices with hardware version C1 and software version 1.1.2_C1_20260211004

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
