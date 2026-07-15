import "hash"
// Salamander CTI  //  https://salacti.com
// GigaWiper: Anatomy of a destructive backdoor assembled from multiple malware

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "GigaWiper, Crucio, FlockWiper, WprFlock, WprCree, CutBrooch"
  condition:
    hash.sha256(0, filesize) == "440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3" or
    hash.sha256(0, filesize) == "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721" or
    hash.sha256(0, filesize) == "db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674" or
    hash.md5(0, filesize) == "a9dbe0025975e3fa764376a437043963" or
    hash.md5(0, filesize) == "be1082aac756fbf3ad7f41c1bc5b9eec" or
    hash.md5(0, filesize) == "62bcb76113ea745020f5e68c8ce9f283" or
    hash.md5(0, filesize) == "fbc2f83b75f3602a281fec095068ea34" or
    hash.md5(0, filesize) == "7c76e51390b0d2e2759fad5ccee2bc30" or
    hash.sha1(0, filesize) == "35953ddaa42da7c71f3efd40d24cf91209c6c473" or
    hash.sha1(0, filesize) == "6f0370309e8cae19e83fbff6f08c1ece3b17b642" or
    hash.sha1(0, filesize) == "9a518770de592df858659f85d2f1a7f10362c304" or
    hash.sha1(0, filesize) == "d2815fe279a904b0f13356df58b8a06f8c6babe0" or
    hash.sha256(0, filesize) == "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001" or
    hash.sha256(0, filesize) == "9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683" or
    hash.sha256(0, filesize) == "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913" or
    hash.sha256(0, filesize) == "f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd" or
    hash.sha1(0, filesize) == "b91be21e984407529691edb1bfe3f97dd4a1ae24" or
    hash.sha256(0, filesize) == "3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd"
}
