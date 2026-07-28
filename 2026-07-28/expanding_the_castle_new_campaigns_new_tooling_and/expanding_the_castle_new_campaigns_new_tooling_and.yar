import "hash"
// Salamander CTI  //  https://salacti.com
// Expanding the Castle: New Campaigns, New Tooling, and the NeedleStealer Connection

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "ClearFake, DarkVNC, Unknown malware"
  condition:
    hash.sha256(0, filesize) == "d26ea6828cc01ae151d99bbee78c4e6d132e9077842a558bce3901fa0970d9be" or
    hash.sha256(0, filesize) == "2fcf553b9656523b3207c08cdf16f7be9a25e55cf8c29f5caf933151c9214367" or
    hash.md5(0, filesize) == "1390903f57b21f346193aefbbfd36759" or
    hash.md5(0, filesize) == "4d5f81bf79554aa7a2187e6ffbc9702a" or
    hash.md5(0, filesize) == "6728b11f74fd435f926ed25c5f2952bb" or
    hash.sha256(0, filesize) == "0c48fd6a18ad9c701b254bbdd412efbf7dfdd2be6534a61c14bce719d259df9f" or
    hash.sha256(0, filesize) == "edff43ecdf7aa476331d925db04e68a2251920165a2109be9df91a56d86b87c7" or
    hash.sha256(0, filesize) == "fa67487da701ce1d61ee3abb84869f669a6c2aa50ca0148a3c4a87e667716638"
}
