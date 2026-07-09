import "hash"
// Salamander CTI  //  https://salacti.com
// Ransomware Analysis: Go Binary and Fast Encryption

rule Salamander_The_Gentlemen
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "The Gentlemen"
    malware = "Gentlemen, Unknown malware"
  condition:
    hash.sha256(0, filesize) == "3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235" or
    hash.md5(0, filesize) == "4200b46a93c6ab059e2b34ce200c4a5b" or
    hash.sha1(0, filesize) == "42bcc743c71a9ea083c1c750a398110582796762" or
    hash.md5(0, filesize) == "ead0d7a8ae0a6ffb7f0a5873fec4ff5e" or
    hash.sha1(0, filesize) == "39bd9c888d3e8110c127ba60cc727d2538bf7da2"
}
