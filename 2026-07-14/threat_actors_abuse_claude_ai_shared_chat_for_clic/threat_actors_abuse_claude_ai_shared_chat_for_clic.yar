import "hash"
// Salamander CTI  //  https://salacti.com
// Threat Actors Abuse claude.ai Shared Chat for ClickFix Malvertising Campaign

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Unknown Stealer, Unknown malware"
  condition:
    false  // no file hashes in this brief
}
