import "hash"
// Salamander CTI  //  https://salacti.com
// Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass

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
