import "hash"
// Salamander CTI  //  https://salacti.com
// TA4922: The Suspected Chinese Crime Group is Going Global

rule Salamander_TA4922
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TA4922"
    malware = "AtlasRAT"
  condition:
    hash.sha256(0, filesize) == "2d2a251a88632f010fd9671789746908eeccaa5bc5c0a5d25e4649efe4f5b15d" or
    hash.md5(0, filesize) == "0ffb16209def5500ff4380d9e8093437" or
    hash.md5(0, filesize) == "3e7066e44132e64360a30974b6ea3671" or
    hash.sha1(0, filesize) == "483a36fb9e4aef9704aa1e4edfb88c492dfe4140" or
    hash.sha1(0, filesize) == "7b2c661cfb69e9c75df90d5102647bb014c28ad5" or
    hash.sha256(0, filesize) == "0857148fb0bc4aa7adf967ede2307bdb4fc427065d5b6a6db132688a5a8e1eb8" or
    hash.sha256(0, filesize) == "3119cf37b8267db8a2dcd11d9a83d5237d7ef1e42388e7c9afa2831b91da8a2d" or
    hash.sha256(0, filesize) == "314f4b59535d1b783e1c20c2be00f9e30f8ed27b2e21fad06a73b47ea43279ef" or
    hash.sha256(0, filesize) == "40b41979b317406f8abc601677a3b93aaf6ef8ab8ac188b8f383735e388f13b5" or
    hash.sha256(0, filesize) == "4fcfa88fffacbce30bbe2136753c9ab5a4c092940d2406fd9d44d5118e745b9d" or
    hash.sha256(0, filesize) == "584a9448dda46bd590d7a2f86228100d2ae6e0d6d990c1a4459ed5ee28e07ae8" or
    hash.sha256(0, filesize) == "66a3836b9a17771bce2161f6b73cbc2494a91e49d6aa30d2d53711e8d10de60d" or
    hash.sha256(0, filesize) == "8c9b6542f73c5c7fe455b52f5101314407da4f65ff48e7ebf6896605e607c8d0" or
    hash.sha256(0, filesize) == "9d0a55c545c4147956db2c2667c4ed931a2875309147548b1dfdd216228f5f73" or
    hash.sha256(0, filesize) == "a648db354820ea4d02940cb1702b35974513b7aae83f6dffaacaac4ba31f9295" or
    hash.sha256(0, filesize) == "a75eab31d7ff06b6864960ad7e633be3f9730ff3d3873e4539c8f425fc632dad" or
    hash.sha256(0, filesize) == "de82998ad5fcd63deae030803388e0fb4290d6223fda82368fd25b99b823f0d2" or
    hash.sha256(0, filesize) == "e0a6a71c605d9a4076147e9537f82f79f1e1eccadc874595160aa4637ff4088c"
}
