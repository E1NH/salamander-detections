import "hash"
// Salamander CTI  //  https://salacti.com
// ACR Stealer: Two observed intrusion chains amid increased threat activity

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "ACR Stealer, Amatera Stealer"
  condition:
    false  // no file hashes in this brief
}
