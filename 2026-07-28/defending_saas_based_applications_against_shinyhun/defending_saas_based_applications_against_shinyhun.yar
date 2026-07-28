import "hash"
// Salamander CTI  //  https://salacti.com
// Defending SaaS-based applications against ShinyHunters OAuth abuse

rule Salamander_ShinyHunters
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "ShinyHunters"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
