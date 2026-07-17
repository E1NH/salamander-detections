import "hash"
// Salamander CTI  //  https://salacti.com
// GoSerpent backdoor attacks in Southeast Asia

rule Salamander_TetrisPhantom
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TetrisPhantom"
    malware = "GoSerpent, McMx, ThumbcacheService, Mimikatz, QuarksDumpLocalHash, Stowaway, TmcLoader, TmcPayload"
  condition:
    hash.md5(0, filesize) == "ebffd5a76aaa690bcdb922f82e0bacc5" or
    hash.md5(0, filesize) == "dc506ff7bb72735444fb3703a6bee6d8" or
    hash.md5(0, filesize) == "d6e86bf8a90e9b632add5fa495f97fbc" or
    hash.md5(0, filesize) == "cb6c4c70a3b171fa3404b8e1a3382116" or
    hash.md5(0, filesize) == "64e9d1950e42bc98486dfd9919463d1c" or
    hash.md5(0, filesize) == "cbbb6d483737ea3566726e51752dff40" or
    hash.md5(0, filesize) == "7f223ee0716ce2ad56f55d3744419449" or
    hash.md5(0, filesize) == "19f8befcb035f52bf70094e6b4f5779a" or
    hash.md5(0, filesize) == "846ef7c1c7323849b2a778c5e4cda162" or
    hash.md5(0, filesize) == "d08a059e8b815e3b891505bc8777fc28" or
    hash.md5(0, filesize) == "93a1569d5d5ab2c4761fedf84f83709e" or
    hash.md5(0, filesize) == "31323334353637383930616263646566"
}
