import "hash"
// Salamander CTI  //  https://salacti.com
// The Permanent Threat: Analyzing Blockchain-Based C2 Operations and Communications

rule Salamander_LenAI
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "LenAI"
    malware = "Sliver, Unknown Stealer, Unknown malware"
  condition:
    hash.sha256(0, filesize) == "5bfb25b8255b61e5ffdf6804451534bcfa9f1dfd225e6c8cdcefb5f50d846898" or
    hash.sha256(0, filesize) == "1505eda3da68e2ff9919b55a31018bd30a991236f041aee835f3bc4e430ce505" or
    hash.sha256(0, filesize) == "f2a326cff405299e4ebdfaac955c52fc7e496544eaa0921ecad4816cb3ae3a27" or
    hash.sha256(0, filesize) == "4e24bbd0fabac6c3efcec943046afbfd332b2c0108a13becfda23a0e26f9ff5f" or
    hash.sha256(0, filesize) == "81bb80d9c5a97dc41b65f6248c131963c91346eb4fb672836b3d53ae67564d9f" or
    hash.sha256(0, filesize) == "ea1b6ff3a0c1a749b9f09d66789973321d63d8896b48f7345193bdad512950a2" or
    hash.md5(0, filesize) == "673a51a179a78fbdf2b8770f868f883a" or
    hash.md5(0, filesize) == "848b1440f5f52bfddf2e1b3e9e248f12" or
    hash.md5(0, filesize) == "a45e8679d2695d10a45a3f78268fab64" or
    hash.sha1(0, filesize) == "96f6794fa4b7414e38be4ef497cd8611d50a59ec" or
    hash.sha1(0, filesize) == "d224dde23da2faff57235192333fc7998762c645" or
    hash.sha1(0, filesize) == "d3e0f9448c94b1017f26e4da63b710a886a2b426" or
    hash.md5(0, filesize) == "1ef50e9d715245e29220936a66c0bece" or
    hash.md5(0, filesize) == "66575cc1df33e40a47fe00abdc067fe5" or
    hash.md5(0, filesize) == "cd8b231a2101c7de3f0b118f99279cbd" or
    hash.sha1(0, filesize) == "326a4305420a5c57950a7ee8c1e41b31132dd027" or
    hash.sha1(0, filesize) == "b51a50ffc57565c8488cb8101252db0e60619750" or
    hash.sha1(0, filesize) == "cfd101963a4e791fc59bda97bfc87f33ce7ce379"
}
