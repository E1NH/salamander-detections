import "hash"
// Salamander CTI  //  https://salacti.com
// The Patch Wars have begun

rule Salamander_UAT_11795
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "UAT-11795"
    malware = "Starland RAT, WLDR agent, CastleStealer, Remcos RAT"
  condition:
    hash.md5(0, filesize) == "38de5b216c33833af710e88f7f64fc98" or
    hash.sha256(0, filesize) == "9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507" or
    hash.sha256(0, filesize) == "9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f" or
    hash.sha1(0, filesize) == "66c72019eafa41bbf3e708cc3824c7c4447bdab6" or
    hash.md5(0, filesize) == "2915b3f8b703eb744fc54c81f4a9c67f" or
    hash.md5(0, filesize) == "c2efb2dcacba6d3ccc175b6ce1b7ed0a" or
    hash.sha1(0, filesize) == "b34d42e320d6674d7747fcb93083c6d59feadb99" or
    hash.sha256(0, filesize) == "90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59" or
    hash.md5(0, filesize) == "0398df5a18f71efcfeef4571a2cef577" or
    hash.sha256(0, filesize) == "b8be9a5e0a191050f9099c11c155b436863e9bc43bc904cdb842e249679aa35a"
}
