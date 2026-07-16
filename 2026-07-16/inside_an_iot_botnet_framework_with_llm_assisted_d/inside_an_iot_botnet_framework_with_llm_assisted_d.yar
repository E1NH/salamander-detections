import "hash"
// Salamander CTI  //  https://salacti.com
// Inside an IoT Botnet Framework With LLM-Assisted Development

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "TuxBot v3 Evolution, AISURU, Kaitori, Tsunami, Mirai, Gafgyt, MHDDoS"
  condition:
    hash.sha256(0, filesize) == "71dfbb171eca4ef9d02ff630b56e5283bbef7b375d4dbe9e8c9531bef312fa8d" or
    hash.md5(0, filesize) == "50eadccdd0f2182bdc9f74aa7b3250b5" or
    hash.sha1(0, filesize) == "12c167b69ad8089299fa342bdc22f99bebea7c01" or
    hash.sha1(0, filesize) == "2774a5f5991657eb9b0062cd3da0391c9bad2643" or
    hash.sha1(0, filesize) == "304e14a138b92135aad27bb37f4e9db440401ec2" or
    hash.sha1(0, filesize) == "4cba585d9f208bd712b28f867f908e503ccc9cfe" or
    hash.sha1(0, filesize) == "4e1483737f769e1cee80fa4d7a056a5d8e3b537e" or
    hash.sha1(0, filesize) == "64af594c7f91793813e3d769e63816b143102396" or
    hash.sha1(0, filesize) == "69dc276dde8efcb409411508da55d4cbe28d5600" or
    hash.sha1(0, filesize) == "74fba0bad93bbb0e1eedb196b6efe6af1c0bf23d" or
    hash.sha1(0, filesize) == "7ad840b1945cc346012987727ebcc062431965a4" or
    hash.sha1(0, filesize) == "81670f250f4b3492fd3e00920f9fe7395ecbf85c" or
    hash.sha1(0, filesize) == "877b804892ab218a53420b6dfbd0a2837368d0b5" or
    hash.sha1(0, filesize) == "a70cea846442c18ad265f311b5ced29a4071771d" or
    hash.sha1(0, filesize) == "a8fd13f6b1bdfa87c0f466df69b7e81325b5dd15" or
    hash.sha1(0, filesize) == "adf267caab78a74c4b4dfabe7b578b0a4d639782" or
    hash.sha1(0, filesize) == "b1cc41e2b9ddb11d0c9d03d319531fea9459cdae" or
    hash.sha1(0, filesize) == "b21cdc5e1b96c640a1d553ed518c49729e367823" or
    hash.sha1(0, filesize) == "befb0e4d1cd7d2b4139b55f811993af2c8839e75" or
    hash.sha1(0, filesize) == "cd540bb31909440fd2bf773e6f1480f5b6f12400" or
    hash.sha1(0, filesize) == "e0f8dd23e4fb0086feb42ea0a5dcef70d7b4d17c" or
    hash.sha256(0, filesize) == "0f8bcca3ed65e980da2a1f90a767b7d543be32eeea3e9338d09d4d635a497988" or
    hash.sha256(0, filesize) == "146f6010f6ee082aab13e0148d39baefa77eaba4ff65817b511b08c2092bdfd2" or
    hash.sha256(0, filesize) == "15c17dce89deccd5172285b2650de957918aa1157cde8e4633ae15dfe31f2711" or
    hash.sha256(0, filesize) == "246c97957651de568e61eba1abe572f0b0f960456209995d43d53a0d7cc494a1" or
    hash.sha256(0, filesize) == "2f2c3551762c03da126e45dca6fc2f997c63f0f1bfc21fd0ceed680ac6f083ce" or
    hash.sha256(0, filesize) == "3ec016d637e4c9cd331edd2580a229621ad638e924a4aa29ac0342e9144ace19" or
    hash.sha256(0, filesize) == "511d3ffb4091cbcc94571d9fb3102e8cb424c6e187d01d53ff12078d54929bda"
}
