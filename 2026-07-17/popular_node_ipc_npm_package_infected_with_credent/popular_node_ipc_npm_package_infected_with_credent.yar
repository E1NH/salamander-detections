import "hash"
// Salamander CTI  //  https://salacti.com
// Popular node-ipc npm Package Infected with Credential Stealer

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Shai-Hulud"
  condition:
    hash.sha256(0, filesize) == "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144" or
    hash.sha256(0, filesize) == "78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981" or
    hash.sha256(0, filesize) == "c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea" or
    hash.sha256(0, filesize) == "449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e" or
    hash.sha256(0, filesize) == "bf9d8c0c3ed3ceaa831a13de27f1b1c7c7b7f01d2db4103bfdba4191940b0301"
}
