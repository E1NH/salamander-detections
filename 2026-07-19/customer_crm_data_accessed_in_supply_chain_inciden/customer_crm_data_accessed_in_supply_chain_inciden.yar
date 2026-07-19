import "hash"
// Salamander CTI  //  https://salacti.com
// Customer CRM Data Accessed in Supply Chain Incident

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
