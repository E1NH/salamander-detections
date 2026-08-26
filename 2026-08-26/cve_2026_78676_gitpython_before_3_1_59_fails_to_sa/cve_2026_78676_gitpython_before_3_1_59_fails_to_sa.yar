import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-78676: GitPython before 3.1.59 fails to safely re-serialize multi-line git-config values during w

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
