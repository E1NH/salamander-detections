import "hash"
// Salamander CTI  //  https://salacti.com
// Dolphin X Stealer Targets 300+ Apps and Profiles Users with AI

rule Salamander_Kontraktnik
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Kontraktnik"
    malware = "Dolphin X"
  condition:
    hash.sha256(0, filesize) == "726e7fe23560fe03ea36163d5f510b494f41a78bf811c92ff219f64b4bfe2be0"
}
