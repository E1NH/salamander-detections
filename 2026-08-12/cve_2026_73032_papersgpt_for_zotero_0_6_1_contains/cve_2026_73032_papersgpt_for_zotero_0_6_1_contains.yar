import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-73032: PapersGPT for Zotero 0.6.1 contains a remote code execution vulnerability that allows atta

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
