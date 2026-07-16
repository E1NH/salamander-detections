import "hash"
// Salamander CTI  //  https://salacti.com
// Shared Claude Chats Meet ClickFix

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
