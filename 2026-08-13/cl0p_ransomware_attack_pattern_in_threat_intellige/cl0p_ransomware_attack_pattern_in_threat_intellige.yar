import "hash"
// Salamander CTI  //  https://salacti.com
// Cl0p Ransomware: Attack Pattern in Threat Intelligence

rule Salamander_Cl0p
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Cl0p"
    malware = "LEMURLOOT"
  condition:
    false  // no file hashes in this brief
}
