import "hash"
// Salamander CTI  //  https://salacti.com
// Inside an affiliate panel targeting Microsoft 365

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "ARToken, EvilTokens"
  condition:
    false  // no file hashes in this brief
}
