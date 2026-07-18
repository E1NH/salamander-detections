import "hash"
// Salamander CTI  //  https://salacti.com
// Gamers beware: malicious wallpapers on Steam found stealing accounts

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "DarkComet - S0334, DarkKomet, Fynloski, Krademok, FYNLOS, Lumma, Vidar, RenEngine"
  condition:
    hash.sha256(0, filesize) == "fc586cad94e5a10dd5be6a6ae6096bd02dfbfd094365bec87e788ed0798d6f67" or
    hash.md5(0, filesize) == "18dedc0009f0927cba6425c84cce9883" or
    hash.md5(0, filesize) == "5620f01284329f561b1839a36be55355" or
    hash.md5(0, filesize) == "74414ed4b63aadec039b603c32762b80" or
    hash.md5(0, filesize) == "8c2cc585ad8a13a72a704c0fda0c9854" or
    hash.md5(0, filesize) == "95856f2ce428c728d9781d3296558068" or
    hash.md5(0, filesize) == "c133c3dd9f7d6934598025047df41abf" or
    hash.md5(0, filesize) == "ded08ae5df7f1b12e5fdb767dbbed0b1" or
    hash.sha1(0, filesize) == "59868381885b33f6c8809cd3d945da7d167439a3"
}
