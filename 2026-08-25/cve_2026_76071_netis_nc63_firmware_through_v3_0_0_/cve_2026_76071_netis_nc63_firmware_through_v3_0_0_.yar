import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-76071: Netis NC63 firmware through V3.0.0.3327 contains a stack-based buffer overflow vulnerabili

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
