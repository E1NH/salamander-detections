import "hash"
// Salamander CTI  //  https://salacti.com
// ClickFix campaign delivers macOS infostealer via DMG

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "ClearFake, Unknown malware"
  condition:
    hash.sha256(0, filesize) == "25b6fc4f9c54a28ba7bfc4dfeafb62c99b59ea6f0d17679219b876b321965095" or
    hash.sha256(0, filesize) == "067ad6221b2224d5cdb64e51c5516132d820cf4d7edf9ec170643943e79c04b7" or
    hash.sha256(0, filesize) == "d6f479736ba55d3c4e895c4940d035cf772f3192fb8dc496f09a801aed16d970" or
    hash.sha256(0, filesize) == "833008c03d40422192051584d829d730497108bef31751cceb0cc043dd96bbfb" or
    hash.sha256(0, filesize) == "8111edf01ac6cb5c77e249d4e84fd92a85b5e89c2e2bef92fbe00b6f1cc2aa8e" or
    hash.sha256(0, filesize) == "f0038a5f46720da5982b6984ceef10cf99359432e102b12a0b0657498d36f670"
}
