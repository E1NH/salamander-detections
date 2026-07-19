import "hash"
// Salamander CTI  //  https://salacti.com
// Klue Integration Abused in Salesforce Data Theft | Threat Spotlight

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
