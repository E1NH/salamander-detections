import "hash"
// Salamander CTI  //  https://salacti.com
// An Analysis of ValleyRAT Infection Campaigns from Fake Installers, Japanese Malicious Emails

rule Salamander_SilverFox
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "SilverFox"
    malware = "ValleyRAT"
  condition:
    hash.sha1(0, filesize) == "e8be03f19ada1f5cec74b143e21d4939e781671d" or
    hash.sha1(0, filesize) == "65168c8dd93b16d3b77092fb70c0fa6fba4dffcc" or
    hash.sha1(0, filesize) == "eca7ed7b699835fadc2c2997a2845864e02b8dfe"
}
