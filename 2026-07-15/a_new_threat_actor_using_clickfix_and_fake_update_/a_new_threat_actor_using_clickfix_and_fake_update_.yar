import "hash"
// Salamander CTI  //  https://salacti.com
// A New Threat Actor Using ClickFix and Fake Update Drive-By Attacks in Thousands of Compromised Sites

rule Salamander_DriveSurge
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "DriveSurge"
    malware = "ClearFake, IClickFix, Unknown malware"
  condition:
    hash.md5(0, filesize) == "0ca424475803a1cb54908a81a00bd93f" or
    hash.md5(0, filesize) == "f3926add1a4531ff324a6acb57d40769" or
    hash.sha1(0, filesize) == "a4f0014474278238b5fe78fc2c4182b498012a33" or
    hash.sha256(0, filesize) == "0c62c11e910d7c0d6b6c9800b70e78bfd9220e1f78bd7bb34ae4c3646d05f6e5" or
    hash.sha256(0, filesize) == "29ac78c51bcdfe68c64830bdeb6e41437dd55e2691149741c9b78be03b6c82ea" or
    hash.sha256(0, filesize) == "428bd0b0ac36dfdd223b3953dbe61c0baf227f893310b03e7afe3111462019c6" or
    hash.sha256(0, filesize) == "7aa15de93cf85729ddf970e8d7897f69ece3ca29608f73e784a9ba40c9cea18d" or
    hash.sha256(0, filesize) == "90aecb370dfb1a99a1f7de0a9c6842ab1b664521fddea16b0ec9a91f322646fc" or
    hash.sha256(0, filesize) == "a84b032b49773c2318b11b1164d1aada69e940229aedbf8185c33fc7dd1d2cdf"
}
