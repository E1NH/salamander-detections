import "hash"
// Salamander CTI  //  https://salacti.com
// New Mirai-Based Linux Botnet 'Evooo1Bot' Turns Victims Into Proxies

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Evooo1Bot, Mirai"
  condition:
    false  // no file hashes in this brief
}
