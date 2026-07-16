import "hash"
// Salamander CTI  //  https://salacti.com
// Twitter Feed - nextronresearch - 17-06-2026

rule Salamander_SideCopy
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "SideCopy"
    malware = "pdfdocs RAT"
  condition:
    hash.sha256(0, filesize) == "ad7e4f47f9ddb2f97c8818d89374a82278922bac1bc41209ecd0b5ad027dcb45" or
    hash.sha256(0, filesize) == "b3007c3b0f140df374a6756215bde55409124822203d309dcc82e10aa8115a91" or
    hash.sha256(0, filesize) == "db1cb4aaee4ad2f1b2907b2c2d3393544a6a05f9a4d8819eb0078606402c416c" or
    hash.sha256(0, filesize) == "e9f8a7e6275c263d2a1c9c5c9725addbf484c77c1aa8387093c16f50ebdc11ab"
}
