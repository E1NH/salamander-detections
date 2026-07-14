import "hash"
// Salamander CTI  //  https://salacti.com
// From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Akira, BumbleBee"
  condition:
    hash.sha256(0, filesize) == "a14506c6fb92a5af88a6a44d273edafe10d69ee3d85c8b2a7ac458a22edf68d2" or
    hash.md5(0, filesize) == "a746da514c90f26a187a294fda7edc1b" or
    hash.md5(0, filesize) == "bcee0ab10b23f5999bcdb56c0b4a631a" or
    hash.sha1(0, filesize) == "1b9aa401457d29405c0bcf19cbf19a7028a0d214" or
    hash.sha1(0, filesize) == "f352cec89a56e23dae20cdd62df4d40bc7f22b5e" or
    hash.sha256(0, filesize) == "186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da" or
    hash.sha256(0, filesize) == "18b8e6762afd29a09becae283083c74a19fc09db1f2c3412c42f1b0178bc122a" or
    hash.sha256(0, filesize) == "6ba5d96e52734cbb9246bcc3decf127f780d48fa11587a1a44880c1f04404d23" or
    hash.sha256(0, filesize) == "a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331" or
    hash.sha256(0, filesize) == "de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d" or
    hash.md5(0, filesize) == "ca8646dfc88423bb9fffda811160cebe" or
    hash.sha1(0, filesize) == "febbaf5f08a8e0782ffcce8beef1f2b4e249a52b"
}
