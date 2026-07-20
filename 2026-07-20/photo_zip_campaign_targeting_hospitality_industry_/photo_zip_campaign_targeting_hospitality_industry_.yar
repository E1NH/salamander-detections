import "hash"
// Salamander CTI  //  https://salacti.com
// Photo ZIP campaign targeting hospitality industry delivers Node.js implant for persistent access

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Unknown Loader, Unknown malware, Vidar"
  condition:
    hash.md5(0, filesize) == "01eb459a28a329aaf6b5fa6fc5acdc7e" or
    hash.md5(0, filesize) == "0e5be13d3339b4b2561e5d88127e1bd3" or
    hash.md5(0, filesize) == "17082531775760189576112827972435" or
    hash.md5(0, filesize) == "25908558764390958596189327204542" or
    hash.md5(0, filesize) == "ba8600d349779c4ba0ea37da2e109f11" or
    hash.md5(0, filesize) == "c2d5d410a37d0c51546b1ef4962aff57" or
    hash.sha1(0, filesize) == "29e3cd6c5f1d8a7ad0ce9a4bb5d6e95e6bc33010" or
    hash.sha1(0, filesize) == "9db9b3e55f58553735a25db6702d272cf48495ea" or
    hash.sha1(0, filesize) == "b77835ab95bd5c25472fa352c5204cf15ab42d09" or
    hash.sha1(0, filesize) == "ff4edf35349eb7af8edc60f01eede469bee54efb" or
    hash.sha256(0, filesize) == "04ec44f2618460f5c77c5e56014a512cc03a123c9c5b6b6b1273e2a1681ac2e1" or
    hash.sha256(0, filesize) == "06a2888c1f07119873ccb051221bd8717281494b33585f4242556e6e5e227969" or
    hash.sha256(0, filesize) == "1c693bcdaf1da636eb21c274b21cc2f6c52c62ddd514700783eee83fe13acb0a" or
    hash.sha256(0, filesize) == "1f8daffec5945a13a1e9231f4a76655d4c7ef4560d0c64ca3abfe48f38297cbd" or
    hash.sha256(0, filesize) == "2e5fd01b7949a45937b853eabcf4b03195614cf84338dcaaa97240d1c5301ddc" or
    hash.sha256(0, filesize) == "3f66634f103b80412d1d670b91befab2a74425d2ea76d904c4a7ffae2ae94b44" or
    hash.sha256(0, filesize) == "49cc0e0c3ec060fb354cacee244d4f297aaefb6db66e67a21262d6c4d2eae1bd" or
    hash.sha256(0, filesize) == "63565f15a99769bbcd527a4d53e5cc259d80e1254463ef9c878c2074685558ae" or
    hash.sha256(0, filesize) == "6580de3b74fd635a1d7a887b8f6e5b0c9ac9e90d6e20466ad41489203119cca9" or
    hash.sha256(0, filesize) == "83e970feb3f10692c164f6889f7a026f135c2433e5bf8e662a6e63a3b81267b7"
}
