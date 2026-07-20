import "hash"
// Salamander CTI  //  https://salacti.com
// Popa: From Sourcing to Distribution

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Unknown malware"
  condition:
    hash.md5(0, filesize) == "2227df1207d2c90db46610bd98909032" or
    hash.md5(0, filesize) == "3a69aedb78677993384dfe9b476e3d26" or
    hash.sha1(0, filesize) == "0a14b993fdac34f7a05b6d9d22f5fa9cfc711134" or
    hash.sha1(0, filesize) == "55c0235188c16bd2e18a21fa78d9a39c220b8b73" or
    hash.sha256(0, filesize) == "0b4c112c98993f01ed761e72c2f82827aa49876034df461c1762e95281876c6b" or
    hash.sha256(0, filesize) == "1a92cf241f86584361097d5735948a8170007206db56fe88739c9048767ab862" or
    hash.sha256(0, filesize) == "22c860931f2ed22897b81ef8da16980fc24b2573ec884a153b3ff5df9e0f8cff" or
    hash.sha256(0, filesize) == "254568375315d86121b74db2eb8bfd8ac6bf192768c6ab5d05ca7e66b8990102" or
    hash.sha256(0, filesize) == "2a6f0837007726a1863f2180a9a84a89284dc57e7557857e2a3d1896a69fe6c7" or
    hash.sha256(0, filesize) == "2e04dc8bee038a5771373fc4dbaa4e45f653cd649928199e9ce8098c8b27d64e" or
    hash.sha256(0, filesize) == "51ead7f0490bfe6b432120bbbd63b807277d016911664fb264640bb8b007d756" or
    hash.sha256(0, filesize) == "68022c244a6cc150395ad3bc6648c30de7c1fa7837498ac101a1824e227efa3a" or
    hash.sha256(0, filesize) == "69f524815eeb3b2069ff41a8a12cae0537de8ad9bd856d694fa21bb2af8fada8" or
    hash.sha256(0, filesize) == "79aec671ceb205db1769da6898c9659c7c8297b13929e593050523438c09a44f" or
    hash.sha256(0, filesize) == "a29cdca72822c1f236c53c181d03f0c45907a45f2ef3c4c2da3ef839bfd3b7a6" or
    hash.sha256(0, filesize) == "a806cece4a4fbbe502e6d76035681702d9adde1c6f74c9e1c0547d37d30ddfcf" or
    hash.sha256(0, filesize) == "af93524fd0aac0a790734a0747fcf844ba5f0652b11a0f4a59bbe5aeace0fa75" or
    hash.sha256(0, filesize) == "b8b8d41a8a7eccda90b366fb5a3d2c0f692504984429aaa19b0af0dcd81dec03" or
    hash.sha256(0, filesize) == "bbcc1a208b4bd0a9ffe8799158cd994d82e125acb30b630e774b242f11dd6985" or
    hash.sha256(0, filesize) == "bf0b36dcbbc60dbf83ecac7c56534271e53a16817909306ecc6f15f7b6106730" or
    hash.sha256(0, filesize) == "ca5fd64932a82d3e24a19fe94d8b7636847f4335b8fd8795a63cfa0107e67048" or
    hash.sha256(0, filesize) == "d06b86da3777be0e2156c35f031f503d280a17ee3a1cc531f4c5fb806c0f749b"
}
