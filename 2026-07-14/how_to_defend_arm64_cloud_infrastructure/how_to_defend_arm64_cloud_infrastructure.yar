import "hash"
// Salamander CTI  //  https://salacti.com
// How to defend ARM64 cloud infrastructure

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "e0ab84da2d2783c8cae3624e8ce58b99ad79219753b249671ff7f743abdacc35" or
    hash.sha1(0, filesize) == "838ea8d6b201e2eed181f3fd890f99ecb6178b52" or
    hash.sha1(0, filesize) == "fbf0b6abd651622864eb921f891b3e7c538fc8a9"
}
