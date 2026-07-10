import "hash"
// Salamander CTI  //  https://salacti.com
// Indonesian Banking Sector Threat Landscape

rule Salamander_SilverFox__Mustang_Panda__Amaranth_Drago
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "SilverFox, Mustang Panda, Amaranth-Dragon, Lotus Blossom, Shadow Campaigns, TripleX, ICARUS, The Gen"
    malware = "Cobalt Strike, Unknown malware, ValleyRAT"
  condition:
    hash.sha256(0, filesize) == "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a" or
    hash.sha1(0, filesize) == "09b0bc41f8838949d5a1c442ee2e2ec9ff892fdc" or
    hash.sha1(0, filesize) == "a12db7b72879ac0f46079efd8c67e8ca0621f73b" or
    hash.sha1(0, filesize) == "cc6fd90785a528883b0203138348df8bad69bb1a" or
    hash.sha1(0, filesize) == "f0b182423107a04cf5f09b8559e656242a4fcc89"
}
