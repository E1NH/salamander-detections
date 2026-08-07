import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-50515: Deserialization of untrusted data in Azure Service Bus allows an authorized attacker to ex

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
