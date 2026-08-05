import "hash"
// Salamander CTI  //  https://salacti.com
// JetBrains TeamCity Deserialization of Untrusted Data Vulnerability

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
