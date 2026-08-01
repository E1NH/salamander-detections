import "hash"
// Salamander CTI  //  https://salacti.com
// Fortinet FortiOS Exposure of Sensitive Information to an Unauthorized Actor Vulnerability

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
