import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-71984: MSI Radix AXE6600 router firmware version v781521 contains a command injection vulnerabili

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
