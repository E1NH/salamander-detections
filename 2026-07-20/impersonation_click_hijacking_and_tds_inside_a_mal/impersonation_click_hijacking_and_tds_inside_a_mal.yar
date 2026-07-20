import "hash"
// Salamander CTI  //  https://salacti.com
// Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "ACR Stealer, Remus, RemusStealer, Unknown malware"
  condition:
    hash.sha256(0, filesize) == "87361ba2bb412dcf49f8738f3b8b9b7dccb557ad2e76ea8d98ffa5b098ae3886" or
    hash.md5(0, filesize) == "8c4f8abe69bde5e1a53ca98fe22e13aa" or
    hash.md5(0, filesize) == "bfea4ee8ef934be7a2b4c64a0bad1e92" or
    hash.md5(0, filesize) == "f0ea4c47bc8fec96770d023f1025bcb3" or
    hash.md5(0, filesize) == "f48bf08687948ead049686cdee0e92dd" or
    hash.sha1(0, filesize) == "606966a9ec33765baedf63331595d1168f2a596f" or
    hash.sha1(0, filesize) == "a3d2ea3aa5850ecac5e75b0cc1467bda57dbb776" or
    hash.sha1(0, filesize) == "d6b6eb84b0718cbd02eea586637679b4d77bb34f" or
    hash.sha256(0, filesize) == "15e6df0c95f2147952308e640d55270e9d097639eaebb34d4b352415f1c6bceb" or
    hash.sha256(0, filesize) == "26f2abfc254a59c2386dd46dca16744f7147a0f0366cb6008e1d53219175f44c" or
    hash.sha256(0, filesize) == "2e842eab0c16ddd1a2ec4a56610adb58d115b65a1e08e9b67e7e375f8eed0873" or
    hash.sha256(0, filesize) == "39dc2327fe1e5a56ac5ad9dc02f0386cff3d83dcfdc558cacba42ebb9dcc5ec2" or
    hash.sha256(0, filesize) == "3bb92771e287aa0a8bdd8e5b5bb697427223eaefded3d9b64b5d5c32ad40f3c2" or
    hash.sha256(0, filesize) == "4cdb1f7ac502289119f7f8256f00baaa994e6ecfb4000dcf5e1c46073508fcb3" or
    hash.sha256(0, filesize) == "598b023e56c45b19173e8f96c1c88036d732fec305cf6bf1b9cf4dbe304beb7f" or
    hash.sha256(0, filesize) == "74091f5a8746a1c68d73e1fc1e4e1ff514632ee3f632a8b306f35dabae2d2b64" or
    hash.sha256(0, filesize) == "cbad672d9bd06ce91ce465d049e50696fbaec9d209ca0ab1fd814d993d04bc9b" or
    hash.sha256(0, filesize) == "ce0888df5e28716432013a8ae002437bd3e993fbe8362c5ff9efbddabfe0ab77" or
    hash.sha256(0, filesize) == "e6a1a428a7c09c9946f7c0179d89b263f442dc3208b5144a9146c200e4185bd6"
}
