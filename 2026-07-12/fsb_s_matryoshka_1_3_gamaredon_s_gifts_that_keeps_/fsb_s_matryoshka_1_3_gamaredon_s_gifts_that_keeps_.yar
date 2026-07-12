import "hash"
// Salamander CTI  //  https://salacti.com
// FSB’s matryoshka #1/3 – Gamaredon’s gifts that keeps unpacking – GammaPhish and GammaWorm

rule Salamander_Gamaredon
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Gamaredon"
    malware = "GammaPhish, GammaLoad, GammaWorm, GammaSteal, Pteranodon - S0147, Pterodo"
  condition:
    hash.md5(0, filesize) == "1794369214b7f62e70a0485e61335c61" or
    hash.md5(0, filesize) == "8e1624d110c090ff57d4b493a9107c66"
}
