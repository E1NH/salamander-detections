import "hash"
// Salamander CTI  //  https://salacti.com
// Dissecting Vanta Stealer, a Python-Based Cross-Platform Information Theft Malware

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Vanta Stealer"
  condition:
    hash.sha256(0, filesize) == "3bff25e745707056cf4ed6428ee8aace9a1bff2fb4030e32a7c0470a34cbfa62" or
    hash.sha256(0, filesize) == "4bdf15157fc0067af179d11e9ad168816ce99a849fd45332482b0b88a05aeabb" or
    hash.sha256(0, filesize) == "5dbddac39fda06acc703c22935fa24e0b4bcdbc26624a1869fe93cd568cdb9fc" or
    hash.sha256(0, filesize) == "6f20836eef6496695e5f2a5fd81e7dfb8770df38fb1bf67fcf024c1261352daa" or
    hash.sha256(0, filesize) == "09e3ce307b2af3f94a315eba97c094d8d755b3674208cc47ceab3c1630a84ad9" or
    hash.sha256(0, filesize) == "026c85b97a6ddac14c9835d0580228c0a82dd82ce12d8d921c2f3067a12bbb7e" or
    hash.sha256(0, filesize) == "31f3e50e764a090d2dbf759e6cb5f678c5c6a3a5a96ff3a2069ffda520580e52" or
    hash.sha256(0, filesize) == "34a01c2429161a8711adff3495ab1dee4419511c8f45c483f50ac71205f68512" or
    hash.sha256(0, filesize) == "44d48b4876cc99f1781877eae9d1e22e99925079a5a8cd0d9022176f5757baaf" or
    hash.sha256(0, filesize) == "64d85df47edd0187462786ff290f34b080f909a5dda946fa7e83fa3f40aaa878" or
    hash.sha256(0, filesize) == "96cc8dc992e465f5f959c7d1481e3789067a78c83706a3dd7ba5a20eaf32b701" or
    hash.sha256(0, filesize) == "467c192e3aeafbac29ab272575bc76545f371a50670fb4a1cf3104dae30622e0" or
    hash.sha256(0, filesize) == "785d6372f397470c48faa0a9a525b91cb990d0b3ed4b6452e31d75ed179a409c" or
    hash.sha256(0, filesize) == "858fcd9bd05d73d2dcc1496761e2f71fd0bf75fa0ae66eeb7405f788837ec384" or
    hash.sha256(0, filesize) == "3349f0cf1d4f294d7d98ee12e0ce03a40740668b50e5e553d843f233a0021d36" or
    hash.sha256(0, filesize) == "9339c056663e9f57d4b9d34b339cd85048176b9e7d9a20958b7ba190964acd47" or
    hash.sha256(0, filesize) == "a71c4149bcb8a77ca755ff235e91b1e774293cf3d653aaa2c41fe943cd0848f1" or
    hash.sha256(0, filesize) == "aa9268a758b5333d725b4b08350ec35e05b9a86f02d65b83b2d9a51e8859b5cd" or
    hash.sha256(0, filesize) == "b6a7d57fb37a0d9dab8a9e1a81ac6c228fefa4375611bbdf847a775c66cf96c5"
}
