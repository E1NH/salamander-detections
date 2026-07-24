import "hash"
// Salamander CTI  //  https://salacti.com
// Threat Insight: Cybercriminals Abusing Vercel to Deliver Remote Access Malware

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "LogMeIn"
  condition:
    hash.md5(0, filesize) == "322a92b443faefe48fce629e8947e4e2" or
    hash.md5(0, filesize) == "e230bf859e582fe95df0b203892048df" or
    hash.md5(0, filesize) == "f3f8379ce6e0b8f80faf259db2443f13" or
    hash.md5(0, filesize) == "f782c936249b9786cc7fac580da3ae0f" or
    hash.sha1(0, filesize) == "5fd4bcca28553ebe759ec97fcbc3a2a732268f85" or
    hash.sha256(0, filesize) == "0a1a85a026b6d477f59bc3d965b07d0d06e6ff2d34381aff79ea71c38fed802b"
}
