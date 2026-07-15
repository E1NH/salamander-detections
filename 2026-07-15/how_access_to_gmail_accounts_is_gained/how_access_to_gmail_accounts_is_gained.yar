import "hash"
// Salamander CTI  //  https://salacti.com
// How access to Gmail accounts is gained

rule Salamander_ToddyCat
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "ToddyCat"
    malware = "Umbrij, TomBerBil"
  condition:
    hash.md5(0, filesize) == "9f5f2f0fb0a7f5aa9f16b9a7b6dad89f" or
    hash.md5(0, filesize) == "28cb7b261f4eb97e8a4b3b0d32f8def1" or
    hash.md5(0, filesize) == "1ab58838e5790efb22f2d35ab98c0b7d" or
    hash.md5(0, filesize) == "22aaeb4946ba6d2f2e27feb7dbb295de" or
    hash.md5(0, filesize) == "3432dd9ac0df80ef86eb80bd080f839b" or
    hash.md5(0, filesize) == "3d3a621f852c42d97fd7260681e42508" or
    hash.md5(0, filesize) == "a7d7d6c4c3f227f7117261c63b9e23a9" or
    hash.md5(0, filesize) == "bae82a15d1dbfb024617b9b56a8e5f66" or
    hash.md5(0, filesize) == "f169d6d172dfb775895a5e2b1540c854" or
    hash.md5(0, filesize) == "f61fbfb7aa1cd5dc8f70b055b51563e2"
}
