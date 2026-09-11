import "hash"
// Salamander CTI  //  https://salacti.com
// Agents Gone Wild: An AI-Orchestrated Global Campaign Against PaperCut NG/MF

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "c3f7109963b9599eb93fd9a97a4ffa38e672642b35b33608d69e6bbf9f19da4e" or
    hash.sha256(0, filesize) == "14779d0d7ad6be3d7bf9ed78e4ab6016f22dfa7bc8b5d9c43b56011f7fe2ea19" or
    hash.md5(0, filesize) == "528cd4e69ecfa5191adbcf6ef28667bf" or
    hash.md5(0, filesize) == "974decb9ff4c8f9ccb0937c96d513347" or
    hash.md5(0, filesize) == "a6437ac3d6798090a218520985d36a3f" or
    hash.md5(0, filesize) == "ce870a91e8d27e8f663f0687abc60b04" or
    hash.md5(0, filesize) == "fc92dfafa7aa741c5f2b9cbcf75d1d19" or
    hash.sha1(0, filesize) == "159989f088c3d4bc54e1acb93b12924a14db8c0b" or
    hash.sha1(0, filesize) == "4e24bfae6ea02175d367e8ba3fbbc38990e95bc0" or
    hash.sha1(0, filesize) == "577fa0267c491d8aa4531e91b0ba402db24932f4" or
    hash.sha1(0, filesize) == "77e981d0b1b81151a6a7d0966aca1b4a1d0f3022" or
    hash.sha256(0, filesize) == "6dca0ea8a52a323b2ae173ef75d7ebb1cc6f909c855e76676a6478b9e40fb861" or
    hash.sha256(0, filesize) == "c852d56ef0db5f91ee7a5f206b12c3b48dbcca6a5b85baeb0276b9816143489b"
}
