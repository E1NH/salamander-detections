import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-64827: Telenia Software TVox 26.5.3 and prior 26.x versions, and 24.9.21 and prior 24.x versions,

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
