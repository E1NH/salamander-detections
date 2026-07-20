import "hash"
// Salamander CTI  //  https://salacti.com
// How a single ScreenConnect incident exposed a massive campaign

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "AsyncRAT"
  condition:
    hash.md5(0, filesize) == "8e4c57358a66eb14d31abb614ddc68de" or
    hash.sha1(0, filesize) == "c2679a152084f3ebdb39aacb6ec6a23c61a46ae6" or
    hash.sha256(0, filesize) == "6ed15aec7504081c3e14a9f6064d7b754aa283e4adb1a59edf3beff65369bc55" or
    hash.md5(0, filesize) == "01325880efffec546f59490089a3b415" or
    hash.md5(0, filesize) == "0eee9bad07e22415439e854657fa1366" or
    hash.md5(0, filesize) == "1e6a5c7b620d487d0cfc6874c3b77c90" or
    hash.md5(0, filesize) == "479bd3bb617b39cd4a46d0768a2592d4" or
    hash.md5(0, filesize) == "54025ce2a9405039899fe99a1d77e0bb" or
    hash.md5(0, filesize) == "5b7e1fe55bd7b5ea54bd4ed1677e5a26" or
    hash.md5(0, filesize) == "5f96c04e3afae97017b201be112284d2" or
    hash.md5(0, filesize) == "695e794631ef130583368770e7b81e98" or
    hash.md5(0, filesize) == "73bead922109a61e5f9f85771a7812c5" or
    hash.md5(0, filesize) == "776dfd3df9c04bb9fcdd6c1880c3761a" or
    hash.md5(0, filesize) == "83601c3d4ed28e8d2be1b99beb8ec18c" or
    hash.md5(0, filesize) == "87603ea025623b19954e460add532048" or
    hash.md5(0, filesize) == "8f4e8b680d3e8d3f5ac39bd72882f713" or
    hash.md5(0, filesize) == "999a63730c9634481d1d76955a2e76a8" or
    hash.md5(0, filesize) == "9a9ccd8b0e5d05f4ee77667b024844db" or
    hash.md5(0, filesize) == "a40d3aeb0dae5b00bdb3a517f3135bbb" or
    hash.md5(0, filesize) == "a85a5bfdcb7c65ab93043b8cf9e20065" or
    hash.md5(0, filesize) == "b32810973132d11afd61ccee222bbb79" or
    hash.md5(0, filesize) == "bd05fcf80e493cf9aa71ec510319469d" or
    hash.md5(0, filesize) == "edff4f58722c93d7c09ed71899416396" or
    hash.sha1(0, filesize) == "b12b5720404e3d8794d72af064939dd953b6a8e0" or
    hash.sha1(0, filesize) == "ce1349eb9d4b2025d1a0dde651a690c7a471c5b0" or
    hash.sha1(0, filesize) == "d27fc9abbeccb60906d22906ef9a73bd05da2b7a"
}
