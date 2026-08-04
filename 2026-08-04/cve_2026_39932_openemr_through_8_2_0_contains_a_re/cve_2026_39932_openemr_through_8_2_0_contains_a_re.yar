import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-39932: OpenEMR through 8.2.0 contains a remote code execution vulnerability in the document categ

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
