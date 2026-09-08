import "hash"
// Salamander CTI  //  https://salacti.com
// DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors

rule Salamander_APT37
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT37"
    malware = "CurlBack RAT"
  condition:
    hash.sha256(0, filesize) == "5db1b6d52faf60b4f32d6fd0c7c938e4d05d29a14c32ded4a9668357c08b6a91" or
    hash.sha256(0, filesize) == "09739441ed4599bac2f8159028f772f71e4b25c8badfff95574e56d7384f3dbe" or
    hash.sha256(0, filesize) == "fea1bc36632c71e5a839803469ef60ac47595d36b2c50934ac109ade6df06e61" or
    hash.sha256(0, filesize) == "83f7d565b0465546027052b597af46eae3a199e7a91fcc2ab936341147349130" or
    hash.sha256(0, filesize) == "7007a78d50a993cb174c685eba96eb442c9507e38fd9d8e5dffc712f613ec110" or
    hash.sha256(0, filesize) == "6cf1b5e92a9c0756f597a5ddefb38eba32961c52efac7ab2a0aa52c639a8fc53" or
    hash.sha256(0, filesize) == "ed72f4cd8d467b5c5d95ae6aeca4aaeea14d79565d379c1ca5871a714727be16" or
    hash.sha256(0, filesize) == "feeea9d0bf6ae7396d28271baa51ae50df5169ce5d32a516865856f91abc50b3" or
    hash.sha256(0, filesize) == "d53c760c23b4405eb04ad0f20ead375440344b3bdf1fb7854ed12e40d155eabe" or
    hash.sha256(0, filesize) == "2f02b09d61d432134e994ad671258f523bbf289ae6091fd4eae192c60bd51b6f" or
    hash.sha256(0, filesize) == "8f30b57928934ae67478d0e690c91d046e35a638da098d02922a4a88a0fdb66c" or
    hash.sha256(0, filesize) == "a1d8af3a6acb731f07f72040eccb3450c1c83d40e29f736c2a63d35388660be4" or
    hash.sha256(0, filesize) == "12810854c8b2c391b23e2e18b013e873d0369b0637aa3cf993136c07188ba3b8" or
    hash.sha256(0, filesize) == "009a1e2d7a582a24e50cf2ffc2a005482c8e38f22bf5ed416053855f8d054e1e" or
    hash.sha256(0, filesize) == "4bb923eb040aa13ca8fd409c31ee4729c60ddff32e350efe1c5a4a9168a065f5" or
    hash.sha256(0, filesize) == "94630b96f628c96a6bff7904b40ffc9ad67c86f8a4ff6080c3b524831c93f402" or
    hash.sha256(0, filesize) == "72e70936f0dbe459142a1d867617c35f8d0cce5d18c6a49e1090a2a5adc8e558" or
    hash.sha256(0, filesize) == "a8bfab4de81a1acb04aacdf757346946b0f5e30f0c9f402004016d0e425119c7" or
    hash.md5(0, filesize) == "c8c68e629bba773a10ac80012d10bf19" or
    hash.md5(0, filesize) == "ecd427ea8330a4ff73618483e00b9b41"
}
