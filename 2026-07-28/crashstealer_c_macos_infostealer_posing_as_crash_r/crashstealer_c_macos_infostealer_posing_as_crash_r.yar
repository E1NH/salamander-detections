import "hash"
// Salamander CTI  //  https://salacti.com
// CrashStealer: C++ macOS Infostealer Posing as Crash Reporter

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "CrashStealer"
  condition:
    hash.md5(0, filesize) == "ed33a3c8d9e861515623a73b27ea4913" or
    hash.sha1(0, filesize) == "8063358813c37992cfe3fcd92038a0334c14353d" or
    hash.sha256(0, filesize) == "08801f81960cd8c1077b4aa2e8124840d56a272842fdcc73263c9968e787e0bd" or
    hash.sha256(0, filesize) == "09bd60ce11ee4324e2052a439a08676e31aac787edda3f9bd02325390b5db2d2" or
    hash.sha256(0, filesize) == "3a9d703ba7f7564399365db7ab8b04238806ef7a53df0b6822f32b80bf0f5a80" or
    hash.sha256(0, filesize) == "4ed199e27a4dc193468569b221b19180e5ae95cab8df84d92e082b68d33672f5" or
    hash.sha256(0, filesize) == "5bb675af9c403896d5f31611cf42304cf482d16f6f3ab6a868a9aa853aa5c179" or
    hash.sha256(0, filesize) == "81ef05cc4d07cd22cd7cd7099f278dd9b9a3ae8ad4770b3d387892e1c6cfb7d7" or
    hash.sha256(0, filesize) == "88334ea00ff94a366cd2a9283a508b97c269839894fddfe91913f3d92e95b6ab" or
    hash.sha256(0, filesize) == "a1966a6d6f54a025f30d55571d21d6537977ca73ffa734c13494b9c806cd7007" or
    hash.sha256(0, filesize) == "f3857c0b84a24b7fc912d55f8b14c67c23d5837b1a6932164d5d62273d4affeb" or
    hash.sha256(0, filesize) == "fba5bbe87fa351eedf2f3c16653cc9e4196d73604529bb50a609e2d3ebf1828b"
}
