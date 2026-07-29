import "hash"
// Salamander CTI  //  https://salacti.com
// Shai-Hulud-Style npm Worm Hits

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Shai-Hulud"
  condition:
    hash.sha256(0, filesize) == "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96" or
    hash.md5(0, filesize) == "b82e54923f7e440664d2d75bd31588ca" or
    hash.sha1(0, filesize) == "e7d582b98ca80690883175470e96f703ef6dc497"
}
