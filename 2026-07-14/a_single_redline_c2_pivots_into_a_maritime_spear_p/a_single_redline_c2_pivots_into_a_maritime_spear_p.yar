import "hash"
// Salamander CTI  //  https://salacti.com
// A single RedLine C2 pivots into a maritime spear-phishing cluster and attacker-owned infrastructure.

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "RedLine Stealer"
  condition:
    false  // no file hashes in this brief
}
