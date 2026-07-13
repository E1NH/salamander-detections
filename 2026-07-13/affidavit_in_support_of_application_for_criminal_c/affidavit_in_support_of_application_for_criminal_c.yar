import "hash"
// Salamander CTI  //  https://salacti.com
// Affidavit in Support of Application for Criminal Complaint

rule Salamander_Void_Blizzard
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Void Blizzard"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
