import "hash"
// Salamander CTI  //  https://salacti.com
// Inside Kimsuky's Abuse of Legitimate Remote Control Tools Across Northeast Asia

rule Salamander_Kimsuky
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Kimsuky"
    malware = ""
  condition:
    hash.md5(0, filesize) == "eb80f7bddb699784baa9fbf2941eaf4a" or
    hash.sha256(0, filesize) == "b9ad79eaf7a4133f95f24c3b9d976c72f34264dc5c99030f0e57992cb5621f78" or
    hash.sha1(0, filesize) == "df6abbfd20e731689f3c7d2a55f45ac83fbbc40b" or
    hash.md5(0, filesize) == "a2191f29f58b9f0cb576b7459ed6680d" or
    hash.md5(0, filesize) == "c08ea73bac08ea4f4665e9e0b0fdd2a8" or
    hash.md5(0, filesize) == "c774b3980151881d9d546710126b5ded" or
    hash.md5(0, filesize) == "cac69a696fc155717dabe641f22db0c9" or
    hash.md5(0, filesize) == "d7dbce5d25aa483d9c5ec1223ed6bf6e" or
    hash.md5(0, filesize) == "e7da02737751f2f171aed28694b9554e" or
    hash.md5(0, filesize) == "e8aaa4f579e6be788929d3548b31bf6d" or
    hash.md5(0, filesize) == "f3620e42e9c726c65ea7e14e3bf35464" or
    hash.md5(0, filesize) == "f6f7a94c11ea0ee01cbbe674cfac7851"
}
