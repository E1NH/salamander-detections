import "hash"
// Salamander CTI  //  https://salacti.com
// RAT Abuses TON Blockchain to Target Japan's Hotel Industry

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Unknown Loader, Unknown malware, Vidar"
  condition:
    hash.sha256(0, filesize) == "5ec231d3d07530dd4e72127aeed10482d53a9fa6162624b9244ecd7418b73d4c" or
    hash.sha256(0, filesize) == "9a75e798a71c2541f17102128f7c546288bbd3eb30b6b2b4948b17e73873a510" or
    hash.sha256(0, filesize) == "c66119f0e5635c4380441d7a79baf0c02a0ab7ea6cd78de06507fc5dc2c1a5d9"
}
