import "hash"
// Salamander CTI  //  https://salacti.com
// N-able N-central Authentication Bypass Using an Alternate Path or Channel Vulnerability

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
