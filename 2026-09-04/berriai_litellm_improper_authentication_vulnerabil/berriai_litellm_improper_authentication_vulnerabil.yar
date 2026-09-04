import "hash"
// Salamander CTI  //  https://salacti.com
// BerriAI LiteLLM Improper Authentication Vulnerability

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
