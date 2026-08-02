import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-67340: ArcadeDB before 26.7.2 (arcadedb-engine) allows trigger scripts to look up host classes in

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
