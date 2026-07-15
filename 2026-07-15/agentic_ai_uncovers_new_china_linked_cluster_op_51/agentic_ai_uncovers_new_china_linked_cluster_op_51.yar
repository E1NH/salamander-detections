import "hash"
// Salamander CTI  //  https://salacti.com
// Agentic AI Uncovers New China-Linked Cluster OP-512

rule Salamander_OP_512
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "OP-512"
    malware = "GhostKit, BadPotato, SweetPotato, EfsPotato, Meterpreter, PlugX - S0013, Thoper, TVT, DestroyRAT, Sogu, Kaba, Korplug, Cobalt Strike - S0154, Rungan, Gamshen, BadIIS"
  condition:
    false  // no file hashes in this brief
}
