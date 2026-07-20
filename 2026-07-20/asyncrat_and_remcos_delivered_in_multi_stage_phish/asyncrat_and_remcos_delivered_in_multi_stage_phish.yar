import "hash"
// Salamander CTI  //  https://salacti.com
// AsyncRAT and Remcos Delivered in Multi-Stage Phishing Campaign

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Remcos, RemcosRAT"
  condition:
    hash.sha256(0, filesize) == "614115669d093c58539e8183617a62a59aefd1a9a1fddcc7a67508f2fb9e36ab" or
    hash.sha256(0, filesize) == "0b47f8d79e37ebec7edd2333ab70caa1e3e710b310b8201c5447820886ce8d49" or
    hash.sha256(0, filesize) == "248da1553ce35bb6c499a660fcd92bde6e3545b56b65b63308e7b7630f376bfc" or
    hash.sha1(0, filesize) == "5e1172c07877a4d44f3c2f33abb268d7e6b3114e" or
    hash.md5(0, filesize) == "ce3480917a5285a03b9de320354f3e1b" or
    hash.sha256(0, filesize) == "f9f6314fc9f333b1aa92afdd63a98927b85fd01607e907e69b4682d18f31d2a1" or
    hash.sha256(0, filesize) == "49c7b4eb6620917ee7ca796472b7af9f01ea6f7f80391ae7eb7bd8dabe0b7249" or
    hash.md5(0, filesize) == "3e4dadbd55753a77a0d2acd3c333afc7" or
    hash.md5(0, filesize) == "492a0bda6b22583ccdab80b2b8f8f2a0" or
    hash.md5(0, filesize) == "52b725b8144745f2885198d514a805eb" or
    hash.md5(0, filesize) == "59ea75c5850eb80812d991f903a10014" or
    hash.md5(0, filesize) == "5e16dd79001f2faba4569e2abd5b19c0" or
    hash.md5(0, filesize) == "5f51518947c84a2b43483ff3d5404cbd" or
    hash.md5(0, filesize) == "5fc03d7c710b3eb75a9c6534dd1319a7" or
    hash.md5(0, filesize) == "7351447d7eaf36822d9bce9ae0ed3ece" or
    hash.md5(0, filesize) == "a822b55a9a6a8b66c068d22e52d3203f" or
    hash.md5(0, filesize) == "cd2a5eb1bf35cb53b20c75be741ac1f4" or
    hash.md5(0, filesize) == "d526c9bbc38129a8c81afeda08e9aaef" or
    hash.md5(0, filesize) == "d924b7e4d3fc4bc02422057ebe87dcdd" or
    hash.md5(0, filesize) == "f37382f028b294ec539f16b74af6a565" or
    hash.sha1(0, filesize) == "4c3f5e274c160b9943259754dbd23b3656aa8265" or
    hash.sha1(0, filesize) == "50fdee4b9ea69300c2769e613c92a69e4adcc0a8" or
    hash.sha1(0, filesize) == "658af6cba07684a4d5a34547585430ddc37a6efa" or
    hash.sha1(0, filesize) == "6c2f10ec18c34ea9ba423b19e6ccf228ecf47a31" or
    hash.sha1(0, filesize) == "8244d0a2457850ba4c2cc036d02863269272bdfd" or
    hash.sha1(0, filesize) == "a67a1b5cf32bcefab1d84c5eb09f3be808cbc4e1" or
    hash.sha1(0, filesize) == "b7cddd45bf477f1a2f8c4343f213454fe57f9b5f" or
    hash.sha1(0, filesize) == "cd3b3de6c894b9cd3bd3b9cfcf00077adb88877b" or
    hash.sha1(0, filesize) == "d044d5b8ba9c7abc203a0ff5688702c7f45b54cd" or
    hash.sha1(0, filesize) == "e15c7f7f4f951bb444fe77603f903d601d3ad93b" or
    hash.sha1(0, filesize) == "e1f3942742b5cd393673539b3298fab5bdef7b14" or
    hash.sha1(0, filesize) == "eb4866afa868cfa18cb49a3bd62a7019358288d5" or
    hash.sha1(0, filesize) == "f2dd12c3b7d04624433cc6811c6fbf20e3f84e2b" or
    hash.sha256(0, filesize) == "0081bb2de5a6599ee14cba1d0df8ff7dd63fe8b070cd18dd7b11c2adfa5e7876" or
    hash.sha256(0, filesize) == "0542b57b67b021f877969c900214362d62eb2ba56d0645ab4e62838c8c79733a" or
    hash.sha256(0, filesize) == "0e1a306ac4b6770dbc8cb194021a9f32e9a726478db2e39084d4baa892c69521" or
    hash.sha256(0, filesize) == "0f2aa62136bee5996123b88a8a5216ad3822252ddb110c5e66728bd49ec270de" or
    hash.sha256(0, filesize) == "1982710eb67791c9c5ac55e13abad0c24d0210c1383eedbda20855944bfe75bd" or
    hash.sha256(0, filesize) == "1fcaa6fc864faa3b0964accf30c562fc4e9192e530c5c5bbcb5ee03fdfc46163" or
    hash.sha256(0, filesize) == "256f595afb005303a693fe26a03f9fce6d47b225bfc2300e418f5f80a89089d2" or
    hash.sha256(0, filesize) == "2d17adbea1ddca7e827c8e4b46d2ea7cb9e693aff07271e5fcb24765e8385afa" or
    hash.sha256(0, filesize) == "33ad6106da73526090d6a798951015b199fc4634b1a0ee611ca16ff32330eb06" or
    hash.sha256(0, filesize) == "38511e5189d3303d7258d3c889a61f56c5000fe4c91fbaedffc4271f6123038b" or
    hash.sha256(0, filesize) == "3892bcd10df0a5fdf2045f78609d073b89e0ef0ee88b88be6a9e308441a8c52c" or
    hash.sha256(0, filesize) == "3d8e5092a9852b61d8d45bd3c7e2d99907fcaa9a8fd3fe3b9efcbc9255947606" or
    hash.sha256(0, filesize) == "424d69145e60635da0d069aef4f2233db3468c557f01286af8e59e6aa8e5cd60"
}
