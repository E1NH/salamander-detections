import "hash"
// Salamander CTI  //  https://salacti.com
// Roblox, Minecraft, and the Insidious Internet for Children

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
