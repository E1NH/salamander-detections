import "hash"
// Salamander CTI  //  https://salacti.com
// Helpdesk Hijackers: Teams Vishing, Quick Assist, and GoGRPC Backdoor

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "GoGRPC, BlindDoor, RevSocket, PyGRPC, S3Siphon, RSOX"
  condition:
    hash.md5(0, filesize) == "3d1819de80c5a6633bc546f7b07086a4" or
    hash.md5(0, filesize) == "7a818efa2a3af3130a3c4b69260a08aa" or
    hash.md5(0, filesize) == "925dc63fc70de650127f41e00e9ffbf3" or
    hash.md5(0, filesize) == "b42366dcf2612adb43ed0c617bfa98d4" or
    hash.md5(0, filesize) == "b6a74fcadf1efca4e9f01658529556bc" or
    hash.sha1(0, filesize) == "1d93080e7e97cd265e259a5e6f4d76e5583ed211" or
    hash.sha1(0, filesize) == "233dbba4110d6d52d5378eb8ca6e8edb5f271445" or
    hash.sha1(0, filesize) == "3f25712f02617eda348f1703bb1096e8a121ceaf" or
    hash.sha1(0, filesize) == "7ddb7a07d5ecb0056f545306225e7a59a8bc2753" or
    hash.sha1(0, filesize) == "a6491268ab79940dcbb811c32f1b19a988219814" or
    hash.sha256(0, filesize) == "35ea50f16bd5c080c91dbaa3dd4937408ed9563c1d9aa1cd0c751ae58db0eedc" or
    hash.sha256(0, filesize) == "41748648b71a70431123ec48e38868ff8aad3a7a06f5d781c2d2a4f718e7fd91" or
    hash.sha256(0, filesize) == "51edd14233483bcf36e0b0f31451f28eac681fe3f2036f76c02b7ec1bb17ce33" or
    hash.sha256(0, filesize) == "5d53246b0e6b681bc624739a7bead39a61fb07c0f4474b8170112e829c053f85" or
    hash.sha256(0, filesize) == "65af5c3ba2d00967b25b9165d2d3171fa81f209ee0790299805bb907d492a670" or
    hash.sha256(0, filesize) == "66b2b22397cea219266afb8cbbb28fe93997c1444f642a183ac8fc9ca1fabed5" or
    hash.sha256(0, filesize) == "759287052b8cc4f4ce16065857cbc9dba72aab218e709d3419483a95092c6f96" or
    hash.sha256(0, filesize) == "7dcabb6d07d52b92bbf8d659d1ed373fa780e7839fd3d744826a56fc1cd2372f" or
    hash.sha256(0, filesize) == "9136ffb749c6cec13b826cd4f25ffdcf170375889feba9fee28dd74c32578f52" or
    hash.sha256(0, filesize) == "f36bfccf944b5d1e5e306958c1a728e38786c042ee4e536cc44c9d43940b1121" or
    hash.sha256(0, filesize) == "f85960dee17ba587b712cd8cdf89042bcd6ba711c3d5d548bef7c7f0988413f5"
}
