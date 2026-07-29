import "hash"
// Salamander CTI  //  https://salacti.com
// One Email Closer to the Edge: UNK_MassTraction & the Physics of Exploitation

rule Salamander_UNK_MassTraction
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "UNK_MassTraction"
    malware = "IceCube, SquareShell, VShell, SNOWLIGHT"
  condition:
    hash.sha256(0, filesize) == "a02f124c5ce4180bd130a62ee03262f399c33491de3aed36e0b15155ae4926c0"
}
