import "hash"
// Salamander CTI  //  https://salacti.com
// Operation FlutterBridge: The FlutterShell macOS Backdoor

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "FlutterShell"
  condition:
    hash.sha256(0, filesize) == "363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34" or
    hash.md5(0, filesize) == "638b0a77a6d686849a78b500adf5e565" or
    hash.sha1(0, filesize) == "c40126fea6ed24652a3e4e19205075cb02cca3e2" or
    hash.md5(0, filesize) == "605169623267c4eb73693b22b811dc7a" or
    hash.md5(0, filesize) == "b4aa7255af4b016586090a5b451300fa" or
    hash.md5(0, filesize) == "ffd773f157df70291f0910a45a1d8d9a" or
    hash.sha256(0, filesize) == "134517796178a150a1585672be134169d6877082b598d840baa3f37b0222be26" or
    hash.sha256(0, filesize) == "2c5bc9e95e1e9b73e3ba8870a008802899866a2c0e2e10112aefddf7a96af04e" or
    hash.sha256(0, filesize) == "32da1437a2734224406c7e5e8d756f0c0cd58c0c959478571cbfc0cd564d018a" or
    hash.sha256(0, filesize) == "6c3f61d46d4de26b9cb16808bf17c33ae69f651a4b879e7b5612ff7f548e2a82" or
    hash.sha256(0, filesize) == "bf90fb31e6024d7e6616f5acd0e8aa28738a9095a508c1a986e1e974cb9e79a0" or
    hash.sha256(0, filesize) == "cc4f048e66c5ab3c0f1d767bb8fc464d082641f4888ea3cd14ea3775077c4bf2" or
    hash.sha256(0, filesize) == "f544bfab72d380cc20692d8ec9d31ea666785fe225dccd55beab29a3c0fdfad2" or
    hash.sha256(0, filesize) == "fc091ddb4d845280aeb7745cfdb6b7cb0013abc35db9e634f055b8e8fb0b5b1e" or
    hash.sha1(0, filesize) == "a247a63644c3475f436d076f55523ea39afd8c41" or
    hash.sha1(0, filesize) == "bb1e6e2650d3d77d732c5eb5176011f914dd87df"
}
