import "hash"
// Salamander CTI  //  https://salacti.com
// GodDamn Ransomware: Latest Beast Rebrand Uses Malicious Driver to Disable Defenses

rule Salamander_Hyadina
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Hyadina"
    malware = "MimiKatz"
  condition:
    hash.sha256(0, filesize) == "141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944" or
    hash.md5(0, filesize) == "d28f0cfae377553fcb85918c29f4889b" or
    hash.md5(0, filesize) == "df218168bf83d26386dfd4ece7aef2d0" or
    hash.sha1(0, filesize) == "32e24780735a0148c3cc4ce7dda30ed9365397a9" or
    hash.sha1(0, filesize) == "4a3418d78d8fe36b39d1ee5435796369b88a8762" or
    hash.sha256(0, filesize) == "816d7616238958dfe0bb811a063eb3102efd82eff14408f5cab4cb5258bfd019" or
    hash.sha256(0, filesize) == "5e85446910e732111ca9ac90f9ed8b1dee13c3314d2c5117dcf672994ce73bd6" or
    hash.sha256(0, filesize) == "7a313840d25adf94c7bf1d17393f5b991ba8baf50b8cacb7ce0420189c177e26" or
    hash.sha256(0, filesize) == "8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8" or
    hash.sha256(0, filesize) == "c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620" or
    hash.sha256(0, filesize) == "31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc" or
    hash.sha256(0, filesize) == "faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395" or
    hash.md5(0, filesize) == "863fa58aa1fe8a88626625b191d4722e" or
    hash.sha1(0, filesize) == "e7fb4bf69be5ac4583c0c02e26a17bd3cdef4c02" or
    hash.sha256(0, filesize) == "45126297c07c6ef56b51440cd0dc30acf7b3b938e2e9e656334886fe2f81f220" or
    hash.md5(0, filesize) == "fc3b93e042de5fa569a8379d46bce506" or
    hash.sha1(0, filesize) == "1ba499bafaa369be58e795a150403c8729ef5d95" or
    hash.sha256(0, filesize) == "5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd" or
    hash.md5(0, filesize) == "e736229e890a138ccf7810e00a6bb50d" or
    hash.sha1(0, filesize) == "10955a02ef3fd3f80f20062c401bf7960ff6ce94" or
    hash.sha256(0, filesize) == "17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180" or
    hash.sha256(0, filesize) == "2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d" or
    hash.md5(0, filesize) == "07e9f0b8627a95960e79e930fb099e84" or
    hash.sha1(0, filesize) == "56bee9df5833a637f5c54d5911df98b0812fe643" or
    hash.sha1(0, filesize) == "d29670e684e40ddc89b47010c37cbc96737035b6" or
    hash.md5(0, filesize) == "233b795102dd9cd630aebddfe3c15bbb" or
    hash.sha256(0, filesize) == "b29f91a440527fb621d106a2048f6379fff3263c60aeda9c82ff8c1d5ae880a8" or
    hash.md5(0, filesize) == "4277a6be9b121a30564aca6ba32db272" or
    hash.md5(0, filesize) == "8e776dbb71eb8f42dffd3020175edef5" or
    hash.sha1(0, filesize) == "7b01f64b7818d315ef7a2485c4ce2a5d6896cb58" or
    hash.sha1(0, filesize) == "7d33e173819ecd502f790bf6d3da260a82dedfa2" or
    hash.sha256(0, filesize) == "19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d" or
    hash.sha256(0, filesize) == "35296e7a34688ca3e3159bcdf92b4d60ba4173a2369aca531bb7bc959f68ed9c" or
    hash.sha256(0, filesize) == "5c4c98d774eb100f9a89ae4e984c27a4f532e58c7cf8c87046dc87db5a065404" or
    hash.sha256(0, filesize) == "8ff1c1967841a595d996a649c8134b7a5970dcf94624b237d1b089e7c6266167" or
    hash.sha256(0, filesize) == "9fae3f15900e13ec3860a109555ecd33ca43d38907c63438c50a2d6d91bfee1d" or
    hash.sha256(0, filesize) == "e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69" or
    hash.sha256(0, filesize) == "ece33e4b7e2d26eeca8ad9db4439f9801a7a77e332611116156738b1b0316046"
}
