import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-62830: Missing authorization in Azure SRE Agent allows an authorized attacker to elevate privileg

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
