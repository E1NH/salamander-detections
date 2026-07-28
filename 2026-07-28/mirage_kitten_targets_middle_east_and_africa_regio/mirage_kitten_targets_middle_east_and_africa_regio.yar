import "hash"
// Salamander CTI  //  https://salacti.com
// Mirage Kitten targets Middle East and Africa region with new malware

rule Salamander_Mirage_Kitten
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Mirage Kitten"
    malware = "NightLedger, BridgeHead, ArcBridge, TWOSTROKE, Retrograde, MiniFast, MiniUpdate, LIGHTRAIL, POLLBLEND"
  condition:
    hash.md5(0, filesize) == "42f847597109da2a220391bb09d00676" or
    hash.md5(0, filesize) == "5fa15ef96808ea82f0a6176f0bb4b386" or
    hash.md5(0, filesize) == "6038d42af0affd1fb263f470c0956f6b" or
    hash.md5(0, filesize) == "a239e655709a2518dd0b7bdbed163679" or
    hash.md5(0, filesize) == "ae628efa305387b633dce82f9364875b" or
    hash.md5(0, filesize) == "afb1c1583606599c7272cfb33cc6f498" or
    hash.md5(0, filesize) == "c832ecd135781b11f59e3fffb3d2b6ac" or
    hash.md5(0, filesize) == "c90f0efadbf322e5eb1c4103a38c30e6" or
    hash.md5(0, filesize) == "d09b14a2fe01c7363ecc56f5d046162c" or
    hash.md5(0, filesize) == "f7d36cc5904a53252d2bb3d21615134f" or
    hash.sha1(0, filesize) == "6e85d21c17d68c7c7e3e10433a53486c5371c127" or
    hash.sha256(0, filesize) == "c4a9de21aad3e71b08bfbcc827d4c242f8915e763117d254e41febe6df4807cc"
}
