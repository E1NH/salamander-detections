import "hash"
// Salamander CTI  //  https://salacti.com
// June 2026 Threat Trend Report on APT Attacks (South Korea)

rule Salamander_Kimsuky
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Kimsuky"
    malware = "AutoIt backdoor - S0129, XenoRAT, PebbleDash, PrxClient"
  condition:
    hash.md5(0, filesize) == "03e4bef86f3e3e6ea23eb6f017af0c98" or
    hash.md5(0, filesize) == "05c07339603994b36dcfefcce720d03d" or
    hash.md5(0, filesize) == "07bb21d28ae4ab07d62f8deb4343aaeb" or
    hash.md5(0, filesize) == "07ed2c9ed61b60078af0164f061696be" or
    hash.md5(0, filesize) == "0b1de625a89da12bd1fdd292b341bad3"
}
