import "hash"
// Salamander CTI  //  https://salacti.com
// Inside FakeAgent: How a Claude Desktop Malvertising Campaign Hit 29 Organizations with SectopRAT

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "SectopRAT"
  condition:
    hash.md5(0, filesize) == "04dcc1abb68aae9d3ae4901cc140dbb8" or
    hash.md5(0, filesize) == "71fdd6fb7f0acd3e9a6206851452e11b" or
    hash.sha1(0, filesize) == "82011a9ff3692236df69427eb200ba05799205b0" or
    hash.sha1(0, filesize) == "da7a5028b9694c406a881eb85e5acd8ea375a890" or
    hash.sha256(0, filesize) == "1cd58cfba596da296ab1878d74023e00c399345a1b6c2a0e5446c53563f4e3bb" or
    hash.sha256(0, filesize) == "1fe3646d27d286db8123297e06ae7badf3e26f352a04f91b6d82c28869a91664" or
    hash.sha256(0, filesize) == "26bae4d7012bf59847ab4036a065419c3d4ca47e020479f55b3b2c6d0d21394a" or
    hash.sha256(0, filesize) == "f8acb8f5cf88b77a4c27d7fd6856aa299bb178e85f9963c2fbd447d818da3ed0" or
    hash.sha256(0, filesize) == "fd826215add30c1319eefa291b6eaf8ddfa7720cfe816c49aef6fe8a88de7939"
}
