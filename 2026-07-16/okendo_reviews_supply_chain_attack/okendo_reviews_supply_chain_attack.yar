import "hash"
// Salamander CTI  //  https://salacti.com
// Okendo Reviews Supply Chain Attack

rule Salamander_SmartApeSG
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "SmartApeSG"
    malware = "NetSupport, Remcos, StealC, Sectop RAT, SmartRAT"
  condition:
    false  // no file hashes in this brief
}
