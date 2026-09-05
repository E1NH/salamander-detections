import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-85428: MOOS core-moos through 10.4.0 contains an authentication bypass vulnerability in the optio

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
