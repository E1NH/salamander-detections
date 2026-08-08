import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-14526: The AI Copilot – Content Generator plugin for WordPress is vulnerable to authorization byp

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
