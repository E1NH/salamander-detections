import "hash"
// Salamander CTI  //  https://salacti.com
// How attackers are jailbreaking LLMs with CTF framing and how to catch them

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
