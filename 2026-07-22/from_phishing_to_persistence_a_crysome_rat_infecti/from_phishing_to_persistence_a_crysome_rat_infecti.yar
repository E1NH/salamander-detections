import "hash"
// Salamander CTI  //  https://salacti.com
// From Phishing to Persistence: A CrySome RAT Infection Chain Analysis

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "CrySome RAT, WinDefCtl"
  condition:
    hash.sha256(0, filesize) == "ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8" or
    hash.sha1(0, filesize) == "f8a3f28ecbd0b08ecab73ef571f16c3d0bd5e009" or
    hash.md5(0, filesize) == "2f4b5a0d98bc4e5616f2dd04337ae674" or
    hash.sha256(0, filesize) == "ec68666e8f0a3b9870d7177bab684c8dcfb8ca0bc7c8c484a71b2b33ea4e26f4" or
    hash.sha256(0, filesize) == "53f1da8a032115aa682749a114f4cfebcb5ef933400a89b4bbfa84f2057222ff" or
    hash.sha256(0, filesize) == "ced4407f4ac7e43c1a3010a394d111d2ad1b50a2e95668b4e9cfe739235e67bd" or
    hash.sha256(0, filesize) == "b7ca8fd9ebe0a76f16deea315fac7ee94dcb18e6ac2832b5c4cb562fbc6e0ed3" or
    hash.sha256(0, filesize) == "c380268d493e0cba914ce2bc55faa1d7c050c599893c3196fee01fa745e6466a" or
    hash.md5(0, filesize) == "45a2228e44257169210cc5dc06e12a6c" or
    hash.sha1(0, filesize) == "de2df0905ece1a1e7f0a70adf36c75deb06b4e4b"
}
