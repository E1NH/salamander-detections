import "hash"
// Salamander CTI  //  https://salacti.com
// Fake Corepack Site Distributes Infostealer and Proxyware to Developers

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "OpenShield, Apprunner"
  condition:
    false  // no file hashes in this brief
}
