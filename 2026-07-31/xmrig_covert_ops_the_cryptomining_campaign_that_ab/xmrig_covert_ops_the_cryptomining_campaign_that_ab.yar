import "hash"
// Salamander CTI  //  https://salacti.com
// XMRig Covert Ops: The Cryptomining Campaign That Abuses Trusted Access and Deploys Forensic Smokescreens

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "XMRig"
  condition:
    hash.md5(0, filesize) == "17b60d650fc5d1718d7f2ac3a6075d11" or
    hash.sha1(0, filesize) == "88520bcfc741610591a23592f9d4ecb31e34deb5" or
    hash.sha256(0, filesize) == "55c67c844258807c4335f40262777a5307bcf5b537c0492cf869b3328796f838"
}
