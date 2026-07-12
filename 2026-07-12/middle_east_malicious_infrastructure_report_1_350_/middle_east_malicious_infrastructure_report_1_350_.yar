import "hash"
// Salamander CTI  //  https://salacti.com
// Middle East Malicious Infrastructure Report: 1,350+ C2 Servers Mapped Across 98 Providers

rule Salamander_Eagle_Werewolf__ENERGETIC_BEAR__Velvet_T
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Eagle Werewolf, ENERGETIC BEAR, Velvet Tempest, APT28, GrayCharlie"
    malware = "Phorpiex, Twizt, XMRig, LockBit Black, EchoGather, Sliver, SoullessRAT, AquilaRAT, DYNOWIPER, RondoDox, Mirai, Phexia, HellsUchecker, Termite, NetSupport RAT, Tactical RMM, Keitaro, AsyncRAT, Cobalt Strike - S0154, Hajime, Mozi, Acunetix, Gophish, Prism X"
  condition:
    false  // no file hashes in this brief
}
