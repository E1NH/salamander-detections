import "hash"
// Salamander CTI  //  https://salacti.com
// ClickFix Campaign Generated Via AI Delivers SmartRAT

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "SmartRAT, Banana RAT, Remcos RAT, GhostLoader"
  condition:
    hash.md5(0, filesize) == "297eb45f028d44d750297d2f932b9c91" or
    hash.md5(0, filesize) == "3c72e1f37f115b00c3ad6ed31bacfe8a" or
    hash.md5(0, filesize) == "6bf4d4c62b5138ace281ce3d08297787" or
    hash.md5(0, filesize) == "b17ccdb5531555e43f082d6e77c07227"
}
