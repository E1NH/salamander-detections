import "hash"
// Salamander CTI  //  https://salacti.com
// The Gentlemen are knocking: сustom backdoors and evolving tactics

rule Salamander_The_Gentlemen
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "The Gentlemen"
    malware = "Gentlemen"
  condition:
    hash.md5(0, filesize) == "9321a61a25c7961d9f36852ecaa86f55" or
    hash.sha1(0, filesize) == "6afc6b04cf73dd461e4a4956365f25c1f1162387" or
    hash.sha256(0, filesize) == "f8965fdce668692c3785afa3559159f9a18287bc0d53abb21902895a8ecf221b" or
    hash.sha256(0, filesize) == "5af1dae21425dda8311a2044209c308525135e1733eeff5dd20649946c6e054c" or
    hash.md5(0, filesize) == "b6b51508ad6f462c45fe102c85d246c8" or
    hash.sha1(0, filesize) == "96f0dbf52aed0afd43e44500116b04b674f7358e" or
    hash.sha1(0, filesize) == "7556ae58c215b8245a43f764f0676c7a8f0fdd1a" or
    hash.md5(0, filesize) == "8f0577d28c4ff5f71b149f444bfaba8e" or
    hash.sha256(0, filesize) == "9ddae47ff968343a8c32a5344060257fdc08e2a7bdb9a227c8b3a584ee3c9f1e" or
    hash.md5(0, filesize) == "eef8a950952696b018aa9c6da2f5d7ad" or
    hash.sha1(0, filesize) == "1fa071303fb846308571e64727501fb98b1c2be6" or
    hash.sha256(0, filesize) == "5abe477517f51d81061d2e69a9adebdcda80d36667d0afabe103fda4802d33db" or
    hash.sha256(0, filesize) == "5b4f59236a9b950bcd5191b35d19125f60cfb9e1a1e1aa2e4f914b6745dde9df" or
    hash.sha1(0, filesize) == "68fec379f2ae76c3d2ce913f7be650cea1d06990" or
    hash.md5(0, filesize) == "5761bd63da03686fc480245da7bd1e9f" or
    hash.md5(0, filesize) == "6ae7c9a7ea0b8c40a64225734f6bd01d" or
    hash.sha1(0, filesize) == "8468cb5888fb383d25f9144c2b2f61c414cea3f8" or
    hash.sha256(0, filesize) == "b67958afc982cafbe1c3f114b444d7f4c91a88a3e7a86f89ab8795ac2110d1e6" or
    hash.sha256(0, filesize) == "c7f7b5a6e7d93221344e6368c7ab4abf93e162f7567e1a7bcb8786cb8a183a73" or
    hash.md5(0, filesize) == "3b46a729db7ae6af8b19711c9452194d" or
    hash.sha1(0, filesize) == "5aea74bf3e70f38eb596f8002b3c02514daee4f0" or
    hash.sha256(0, filesize) == "1af419b36a5edefef387409e2b3248c9223f7dc49a4f7b15ea095d371c3a70b2" or
    hash.md5(0, filesize) == "10ca9a4040001560d053b7e7885c1b95" or
    hash.sha1(0, filesize) == "e7cc7b32d844ec6a2f41f0efbc64a0783afb56e4" or
    hash.md5(0, filesize) == "02944c8a5535cdb5b2cbb893db2d5acf" or
    hash.md5(0, filesize) == "3c471ebc947cdf32240a90ffadf49b13" or
    hash.md5(0, filesize) == "4be8bb62f0ebbcf4ce52c35ab6f794f5" or
    hash.md5(0, filesize) == "53c616677bc7e2a0a03127f19166d007" or
    hash.md5(0, filesize) == "554e699c96b332468f1ae69c1ae81ef9" or
    hash.md5(0, filesize) == "5c3b9821fc82a9028cb63b9671950919" or
    hash.md5(0, filesize) == "5f0b2c6d9f442754258bf4dd841c8341" or
    hash.md5(0, filesize) == "608faf58353b65c45ef9833358ac3787" or
    hash.md5(0, filesize) == "73f0a8c3ea794a04e80c32038249f044" or
    hash.md5(0, filesize) == "846dc77c1246db20d976346e0e359502" or
    hash.md5(0, filesize) == "adac9984b3cc43d66a0d33079bbec299" or
    hash.md5(0, filesize) == "ae0e536766788478263bf448a9381641" or
    hash.md5(0, filesize) == "b3e418d30312c1b2c58a791286868f42" or
    hash.md5(0, filesize) == "b9986a0f1f1f1a798dc3f0c59a80a1a3" or
    hash.md5(0, filesize) == "c2764744dcb4b0e1db79ca1e8bf65368" or
    hash.md5(0, filesize) == "d12a5b36dd00586cc374a1cae43efed4" or
    hash.md5(0, filesize) == "d2f72897e8986303d5567eb2384932b8" or
    hash.md5(0, filesize) == "de1522f9219497632f30f8a6e72f26b6" or
    hash.md5(0, filesize) == "edb1c480295250dd1a38f3aa1357deae" or
    hash.md5(0, filesize) == "fdae2beb813778b4540a997706862096" or
    hash.sha1(0, filesize) == "ab5ad04bb822435e5453706cd86cc001ee555aee" or
    hash.sha256(0, filesize) == "cb747c0134f99d5033bac6e966864e2435a2a94244ca8e3f614f4992df93ff10"
}
