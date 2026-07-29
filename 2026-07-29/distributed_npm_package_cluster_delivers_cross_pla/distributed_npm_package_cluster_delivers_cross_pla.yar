import "hash"
// Salamander CTI  //  https://salacti.com
// Distributed npm Package Cluster Delivers Cross-Platform RAT Targeting Alibaba Developers

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "lib-mtop, aone-cli"
  condition:
    hash.sha256(0, filesize) == "84a6ccaaab1596139d28e822f40cc99c68d337d4c81d1c6d9692c1d6bb22e4af" or
    hash.sha256(0, filesize) == "6044974c633b3a319c31bb32110411520c425e89722a64806528553227e7a50a" or
    hash.sha256(0, filesize) == "0910ecfa049738ef3f2540855341a380df89224ff71da94b4c21689fd66f62e3" or
    hash.sha256(0, filesize) == "b8b81af76163bdcc5b4f7d8fe6795f164991f8a62678c971db031b9e90a27813" or
    hash.sha256(0, filesize) == "ef9a1896eeaae929800eade768276e2240ef252d26d0d96c1950a1a5e1aadb34" or
    hash.sha256(0, filesize) == "e5d8350f1540fe91145dc262c455bca7748ad97dafb2d9facd5adebed9f66d2d" or
    hash.sha256(0, filesize) == "41957bd0ba2d9c07af2e069f10780fdf6b2102c065bebe0db2136dfe07d67a28" or
    hash.sha256(0, filesize) == "33b58598eb317553942e27545982d4c25ce6120eae10e42393746eb0e02ecae9" or
    hash.md5(0, filesize) == "3201d407b7899a12d6d439950511c6a5"
}
