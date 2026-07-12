import "hash"
// Salamander CTI  //  https://salacti.com
// Prinz Eugen ransomware: a deep dive into a new Go-based encryptor

rule Salamander_ROOTBOY
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "ROOTBOY"
    malware = "Prinz Eugen"
  condition:
    hash.sha256(0, filesize) == "686213cc11d36af764de824801bced9366dfca3823fe0d51b752f74149bcf1f4" or
    hash.md5(0, filesize) == "17dd3f59f13f54a34761cef0c2b73cd7" or
    hash.sha1(0, filesize) == "9d94e2a15b75e1ef4487429ac71fc13e186c4a2d"
}
