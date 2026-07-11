import "hash"
// Salamander CTI  //  https://salacti.com
// From external espionage to domestic targeting

rule Salamander_APT32
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT32"
    malware = "SPECTRALVIPER, Denis - S0354, SOUNDBITE - S0157, PHOREAL - S0158, WINDSHIELD - S0155"
  condition:
    false  // no file hashes in this brief
}
