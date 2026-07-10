import "hash"
// Salamander CTI  //  https://salacti.com
// The Gentleman Ransomware | Defense Evasion TTPs Uncovered

rule Salamander_The_Gentlemen
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "The Gentlemen"
    malware = "The Gentlemen, Qilin, Trojan:Win32/MpTamperBulkExcl.H"
  condition:
    hash.sha256(0, filesize) == "f918535f974591ef031bd0f30a8171e3da27a6754e6426a8ba095f83195661c8"
}
