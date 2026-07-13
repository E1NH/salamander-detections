import "hash"
// Salamander CTI  //  https://salacti.com
// Matryoshka #3/3: Gamaredon's Gammasteel Infostealer

rule Salamander_Gamaredon
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Gamaredon"
    malware = "GammaSteel, GammaLoad, GammaPhish, GammaWorm, GammaWipe"
  condition:
    false  // no file hashes in this brief
}
