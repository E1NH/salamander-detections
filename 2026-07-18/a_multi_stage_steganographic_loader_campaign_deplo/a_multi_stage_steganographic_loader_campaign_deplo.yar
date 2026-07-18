import "hash"
// Salamander CTI  //  https://salacti.com
// A Multi-Stage Steganographic Loader Campaign Deploying Diverse Payloads Globally

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Remcos, RemcosRAT"
  condition:
    hash.sha256(0, filesize) == "372f19a45d0eb4c8c52117c6ae2bb8040a91bc72be8670623f957a18c2166985" or
    hash.md5(0, filesize) == "897abf678edad72998554ec18675092f" or
    hash.md5(0, filesize) == "afe085b7324d72673eef749ff5f21a49" or
    hash.md5(0, filesize) == "c2e25aba8e2ad4cafdd6c633b8ca0906" or
    hash.sha1(0, filesize) == "be36ef651eed6808760153200a3a2a2b7060cce5" or
    hash.md5(0, filesize) == "4924369c0bdaf73b21eb992eb9db4dea" or
    hash.md5(0, filesize) == "f3626a38fcf488c9eed54beb8c7c116f"
}
