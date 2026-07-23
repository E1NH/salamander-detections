import "hash"
// Salamander CTI  //  https://salacti.com
// Abusing Trusted Business Workflows: A Multi-Stage Phantom Stealer Campaign

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Phantom Stealer"
  condition:
    hash.md5(0, filesize) == "34bfa888695b9aaa41bd575245972043" or
    hash.md5(0, filesize) == "5f238710a5ef4f6ddbbe7a118c822705" or
    hash.md5(0, filesize) == "6bbfc88534d5d515dddb0ec9bb618530" or
    hash.md5(0, filesize) == "8a620e451e64f418bc21fd458e952f2e" or
    hash.md5(0, filesize) == "a30b628d0c087f305b35be3e3f5281b3" or
    hash.sha1(0, filesize) == "ddb91e512fa3ae6a38eed741868526ffbc40a864" or
    hash.sha256(0, filesize) == "64a68e4e1b93f1347c0935875395672784db5b49027c6508f13983efa98971f8"
}
