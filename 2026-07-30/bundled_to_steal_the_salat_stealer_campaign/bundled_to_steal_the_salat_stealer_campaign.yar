import "hash"
// Salamander CTI  //  https://salacti.com
// Bundled to Steal: The Salat Stealer Campaign

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "SalatStealer"
  condition:
    hash.sha256(0, filesize) == "60118ba6124480d1c28b3d30f380aa64030418ba1774e8437f9cfae5ea191271" or
    hash.sha256(0, filesize) == "075b3caa3a754c23f929a1591c6b333c7da1080a5fdf8ea2a3497d1505b60dde" or
    hash.sha256(0, filesize) == "7376aaca33eab974ec527d44753d8016c1d305e2db935189a91a57b0ecbb3ccd" or
    hash.md5(0, filesize) == "d6c7ca66c4fef2bf7c62261f58f2f6ab" or
    hash.sha1(0, filesize) == "7e6f8597028e4dc2ff63ed330f989fe9dbca3093" or
    hash.sha256(0, filesize) == "347e3ef094831fd280628c711804603f695b020e365606174a6ba118ebf56cff" or
    hash.md5(0, filesize) == "742be0bf09856460bc85f9674d6914c7" or
    hash.sha1(0, filesize) == "3711d405a68a926f73df57c886845a1c7928b778" or
    hash.sha256(0, filesize) == "7018dc48efdf1311d644225e3c9e5f8f6d49863dbaca315f16d25473f127978d" or
    hash.sha256(0, filesize) == "fec793499d9df0458b611a71dda23b41ba1c28038a79924ab606937e26e77115"
}
