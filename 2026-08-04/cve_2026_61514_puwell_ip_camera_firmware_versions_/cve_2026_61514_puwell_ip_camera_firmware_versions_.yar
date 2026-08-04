import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-61514: Puwell IP Camera firmware versions 2.x through 4.x contains an authentication bypass vulne

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
