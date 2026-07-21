import "hash"
// Salamander CTI  //  https://salacti.com
// ​​Kratos PhaaS Targets US and EU: How to Reduce Microsoft 365 Account Takeover Risk​

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
