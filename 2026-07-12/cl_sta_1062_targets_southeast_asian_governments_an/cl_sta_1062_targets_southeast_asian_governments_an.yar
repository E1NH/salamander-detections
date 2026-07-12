import "hash"
// Salamander CTI  //  https://salacti.com
// CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure

rule Salamander_CL_STA_1062
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "CL-STA-1062"
    malware = "TinyRCT, Mimikatz, JuicyPotato"
  condition:
    hash.sha256(0, filesize) == "f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1" or
    hash.md5(0, filesize) == "2b1ddacbc18763bd8e194c58aea54a4b" or
    hash.sha1(0, filesize) == "bb47d7ce616b2c11864c30dedb5e3c0402e782a6" or
    hash.sha256(0, filesize) == "00e09754526d0fe836ba27e3144ae161b0ecd3774abec5560504a16a67f0087c" or
    hash.sha256(0, filesize) == "4e1f8888d020decd09799ec946f1bf677cac6612b24582ddbf4d8ede425d8384" or
    hash.sha256(0, filesize) == "9b481b69cd91b09fa7bae7428f646dd89473a4c03393e43da81fe756cde1c472" or
    hash.sha256(0, filesize) == "cbfe8de6ffadbb1d396f61e63eb18e8b11c29527c1528641e3223d4c516cf7c3" or
    hash.sha256(0, filesize) == "dce5df29bddff5a4ddaea5c4fec14da91f7b69063a6e1c45ed61e5da4fc6c87b"
}
