import "hash"
// Salamander CTI  //  https://salacti.com
// Melofee: a look back at a Linux implant and its new variants

rule Salamander_APT41
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT41"
    malware = "Melofee, ShadowPad - S0596, POISONPLUG.SHADOW, HelloBot, PlugX - S0013, Thoper, TVT, DestroyRAT, Sogu, Kaba, Korplug, Spark - S0543, Cobalt Strike - S0154, StowAway, CrowDoor, TernDoor, Hemigate, RatelS, Reptile"
  condition:
    hash.md5(0, filesize) == "40637c70fd5cd899ca41d1252c267ccf" or
    hash.sha1(0, filesize) == "71d3832587a1d009ca3c0947005b187f23e52008" or
    hash.sha1(0, filesize) == "b6df18f66cf4364be2946d6b981e69763aafde68" or
    hash.sha1(0, filesize) == "dbbcb279a1f1a258832174ce63c295c5080de249" or
    hash.sha256(0, filesize) == "0c1666b274ddb44dd5c7a11f03c8c041f6bccf0c7dae924626ef9d15b1cc41d5" or
    hash.sha256(0, filesize) == "129349a221e6efcc9a047efdfd81197f796fcf38877344f17f85651b21e33427" or
    hash.sha256(0, filesize) == "4400096e8b39cb2641abec17c6dddad845ed6415e79d60adc2af1dcbd2837c59" or
    hash.sha256(0, filesize) == "50daadd49b8df4f0190d0badfde89f8e6a6e61af664ef1444984028a005f40d8" or
    hash.sha256(0, filesize) == "6678216ace0ff224d6a5ae6bf1ca29e66fba9fceaa715e27440e85d5bfb06069" or
    hash.sha256(0, filesize) == "8255d5a423ce79c69e42685cbf8e708b4239650c01b2898a7efe856582bb3aaf" or
    hash.sha256(0, filesize) == "9d01724193d9570a6c75bbcbb171d29df290207007d004cf75d133dd9aa475f4" or
    hash.sha256(0, filesize) == "aa2fd252a6f5a09b8d8422fbd1037febefe2aa99317e3c3973889384a80e29b7" or
    hash.sha256(0, filesize) == "cbce7dc8649b37c5db411dfee3a74e8cace2b48fdc8350bfa5b4846c5d9ed2ae" or
    hash.sha256(0, filesize) == "dd081c130d7c3a3c18e06a26300dcfd65ee70e6b23b729edb54cb0f0a5829df9" or
    hash.sha1(0, filesize) == "c8e585c8a161b9b7a0e59bd65a3ec5492375d53c"
}
