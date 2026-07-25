import "hash"
// Salamander CTI  //  https://salacti.com
// Investigation of email-based attack delivering MediaFire ZIP file with execution chain analysis

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "NetSupport RMM"
  condition:
    false  // no file hashes in this brief
}
