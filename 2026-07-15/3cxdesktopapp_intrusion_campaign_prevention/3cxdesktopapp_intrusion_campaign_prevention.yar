import "hash"
// Salamander CTI  //  https://salacti.com
// 3CXDesktopApp Intrusion Campaign Prevention

rule Salamander_Lazarus_Group
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Lazarus Group"
    malware = "TxRLoader, ArcfeedLoader"
  condition:
    hash.sha256(0, filesize) == "5407cda7d3a75e7b1e030b1f33337a56f293578ffa8b3ae19c671051ed314290" or
    hash.sha256(0, filesize) == "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983" or
    hash.sha256(0, filesize) == "92005051ae314d61074ed94a52e76b1c3e21e7f0e8c1d1fdd497a006ce45fa61" or
    hash.sha256(0, filesize) == "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868" or
    hash.sha256(0, filesize) == "b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb" or
    hash.sha256(0, filesize) == "dde03348075512796241389dfea5560c20a3d2a2eac95c894e7bbed5e85a0acc" or
    hash.sha256(0, filesize) == "e6bbc33815b9f20b0cf832d7401dd893fbc467c800728b5891336706da0dbcec" or
    hash.sha256(0, filesize) == "fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405" or
    hash.sha256(0, filesize) == "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
}
