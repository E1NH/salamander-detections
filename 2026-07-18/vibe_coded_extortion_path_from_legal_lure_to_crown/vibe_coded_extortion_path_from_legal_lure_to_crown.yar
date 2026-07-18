import "hash"
// Salamander CTI  //  https://salacti.com
// Vibe Coded Extortion: Path from Legal Lure to CrownX Ransom Capabilities

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Avalon, CrownX"
  condition:
    hash.md5(0, filesize) == "c3587edc48c37656b29bcd3da9458eea" or
    hash.sha256(0, filesize) == "4b7301f02b8312ae6de614981f325dbbabee32166630618fdff74615d9a487ba" or
    hash.sha256(0, filesize) == "59a260716d05c20229c6a46fe0a2fb5b80fa30c9c73a850222d9d3454426a60a" or
    hash.sha256(0, filesize) == "607cb58b8a592885eef5cfbe35ddce962741b0775c575f58cb3a96ca0ee893a6" or
    hash.sha256(0, filesize) == "adbc18f15019ef2ba6890b7996445c14350d57ba772eb33182889bc14ac47085" or
    hash.sha256(0, filesize) == "b7d50d0406afcd2efd87bf3bf8c4211719ba9817dd2e0ad62af10c933e765e28" or
    hash.sha256(0, filesize) == "c725815cbb07ab5be8903e74ef8aea46ef9c25e4a3bc626ae94bfc1ae21df6e3" or
    hash.sha256(0, filesize) == "e3ec5926a167d6e3359f98cdfb7ac3b2cce97652843056505d02e6d2898573c6"
}
