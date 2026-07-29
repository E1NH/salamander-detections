import "hash"
// Salamander CTI  //  https://salacti.com
// Phishers Abuse Business Account Manager Service

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
