import "hash"
// Salamander CTI  //  https://salacti.com
// Ukraine's UAV Supply Chain Targeted With Besomar-Themed Malware Chain

rule Salamander_GhostShell
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "GhostShell"
    malware = "Cobalt Strike, GhostShell, Vidar"
  condition:
    hash.sha256(0, filesize) == "ab5681266f70af7df24383f15de876e411fc18e35cb6f24603b12f580b05ccb3" or
    hash.sha256(0, filesize) == "8de34006dafd990853a45cbe9aaab4ee18c8cd4c1ad0a98fe71f8d63cd60db25" or
    hash.sha256(0, filesize) == "b1834634820ae696f0514ca2b6723061f115857232306e573f4d115bc6ead012" or
    hash.md5(0, filesize) == "16a59e1fece21ca5394a8ec9ea596fec" or
    hash.md5(0, filesize) == "6da30ad8677b058fad4d3d3031a428ec" or
    hash.md5(0, filesize) == "d0a66dd44ee64b76de79cddab13d2745" or
    hash.sha1(0, filesize) == "4b5f407f5966f49f8c1005a94a822c83b20fa325" or
    hash.sha1(0, filesize) == "52a1b02e4fe0998069c777bec37eb394781e8fda" or
    hash.sha1(0, filesize) == "c4834de90f419c5517f3a1c13d219d71fc85e742"
}
