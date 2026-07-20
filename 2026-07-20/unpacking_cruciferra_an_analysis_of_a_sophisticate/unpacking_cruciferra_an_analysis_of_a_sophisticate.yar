import "hash"
// Salamander CTI  //  https://salacti.com
// Unpacking "Cruciferra": An Analysis of a Sophisticated Crypter Service

rule Salamander_TA4922
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TA4922"
    malware = "StormKitty, XWorm"
  condition:
    hash.sha256(0, filesize) == "09bedbf7a41e0f8dabe4f41d331db58373ce15b2e9204540873a1884f38bdde1" or
    hash.sha256(0, filesize) == "5b4f59236a9b950bcd5191b35d19125f60cfb9e1a1e1aa2e4f914b6745dde9df" or
    hash.sha1(0, filesize) == "68fec379f2ae76c3d2ce913f7be650cea1d06990" or
    hash.md5(0, filesize) == "5761bd63da03686fc480245da7bd1e9f" or
    hash.md5(0, filesize) == "4f1773a1228e2c009cbcf61e9e550e01" or
    hash.sha1(0, filesize) == "2aa47fb23074e8ae776a369f9e28d1a2f6e70739" or
    hash.sha256(0, filesize) == "17aae57cf6255c7eb169bf62ea67376d9708976eb7831f8cdd0ea38bdcb37dc4" or
    hash.sha1(0, filesize) == "bc61ef6d7ad9ee878028f24d50e9dcf6d7d88bf2" or
    hash.md5(0, filesize) == "26b2da88cb95b98b46bb985f67f76154" or
    hash.sha256(0, filesize) == "2fdfdd13a0c548bb68c9d5aa8599a9265d4659da3e237fe7a42ac6ac06b9a06a" or
    hash.sha256(0, filesize) == "3c181f642e24c28602a87be7f195e2f3d1ffa30b37e20f5121d99f88b22ab80e" or
    hash.md5(0, filesize) == "63bfd6567f4c704e8ed6530f5cdd704e" or
    hash.sha1(0, filesize) == "080fdb73a6bbc99625c2190730257d1e54723952" or
    hash.sha256(0, filesize) == "3f31aee0948d16f8d64bf6bec69a4331099993e502b11bfc56b2c0112024489d" or
    hash.sha256(0, filesize) == "59ad96dd3b4d5f10a5c53bbd465446e52dc7701a4ac633632f762bf1336d3347" or
    hash.sha256(0, filesize) == "66dbe675480dc229e5b3ab8ad74207f73486e64e57805074f784bb2e01bcb865" or
    hash.sha256(0, filesize) == "6dbd6f9f2fa636c16ac4fa81418b68a604424861b9650dd9c4f2b0ba6f67d6ac" or
    hash.sha256(0, filesize) == "7887e919555fb5948c217556ba149392a72982b1bc427d3db779db9dcbf09ee8" or
    hash.sha256(0, filesize) == "a6fb779be35592fb0ff624a8f8e12ab3cafe7bcfc312cd98263814db7fb01e02" or
    hash.sha256(0, filesize) == "c46e907886e2158cbc453e767183aecf07887b5ac8848f19684451883d69f5f0" or
    hash.sha256(0, filesize) == "c4e93449453cf67c5d5605bb8f425207a738a242fdb432d720acc32faa74926c" or
    hash.sha256(0, filesize) == "c5b1e9aafc8f2b4ab05effc00fd43f3114b9ef1d592a086c952793ac4e299809"
}
