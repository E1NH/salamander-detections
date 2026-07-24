import "hash"
// Salamander CTI  //  https://salacti.com
// Indirect Prompt Injection in Web Content Targets AI Agents

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
