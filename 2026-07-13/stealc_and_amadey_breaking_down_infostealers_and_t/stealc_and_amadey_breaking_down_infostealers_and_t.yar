import "hash"
// Salamander CTI  //  https://salacti.com
// StealC and Amadey: Breaking down infostealers and the cybercrime services that deliver them

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Amadey, Stealc"
  condition:
    hash.md5(0, filesize) == "f89ad7e92c7de6945ce0878e470e388b" or
    hash.sha1(0, filesize) == "d4f8f562b4a109cccbc0dbdf28bc6d033d7891fb" or
    hash.sha256(0, filesize) == "8cef760d11d24fc2e9bbd9f770dca5105854f7ece3b0e6948d7c8b7fdd1765ea" or
    hash.sha256(0, filesize) == "98e504cc7125b79eda5491f40b998605a05f4cd968b961aab4cce7beb074fefe" or
    hash.sha256(0, filesize) == "0215f734867bd71c57ff5c524d8cc670be5b4f1861b2c390cf46d18784a53624" or
    hash.md5(0, filesize) == "349c233c4e1b6c0724e5ec84df16188d" or
    hash.md5(0, filesize) == "95b318d953fd939f284efe2be78fe95b" or
    hash.md5(0, filesize) == "a025b901a7979bff2a6c6e4e74c7c76a" or
    hash.sha1(0, filesize) == "2f3d86e77248b23ef93b7b8c2a9915b2eace5d46" or
    hash.sha1(0, filesize) == "72cab50156ba4e2d5f4de97f672d4635e98ddacc" or
    hash.sha1(0, filesize) == "7493c316df2727dd19ef14593fcc014bdb2a0d4b" or
    hash.sha256(0, filesize) == "1246c5b89ab668c1137f377507bc3e266a98e93248382aa026610ae1e764a497" or
    hash.sha256(0, filesize) == "2a0f053855da59b3b56812e580d7baeba59fc9493694722aa9e3f121ee3363f1" or
    hash.sha256(0, filesize) == "30cef3d3d956e83e2c50579cfbe57a49159cccbcc8b0b0422f27d55e1c401ad9" or
    hash.sha256(0, filesize) == "43455f1ff4a623b783da670d052eb77eaaacb0c66a9f1e8508f802bf22e8129e" or
    hash.sha256(0, filesize) == "5f5b25b2e35d404034d0d60975cf1ffbc6f141761ec3f4f15d6f7c6213a056f6" or
    hash.sha256(0, filesize) == "8f32456359f209a63adfd24b94235e1727382ac7f7bb7f2bcaf754e721925b64" or
    hash.sha256(0, filesize) == "9383572a30ae5b76fadd0700fbd7a1aa7b05d0b6c8f9cdaef9b30a3e1f65d57d" or
    hash.sha256(0, filesize) == "977b33a9b481cf714946b7d386865cd5d284312aa5ecfa0546c197b1003e1bde" or
    hash.sha256(0, filesize) == "99507f18c4e61fdb109805404bf6a79ea8ce2fddc590ce48d717e97516ab7e8d" or
    hash.sha256(0, filesize) == "b7d1f172ff3feafe65d47fd1cbe0cc249316371ae0e1cbe3a7c741c738b3353d" or
    hash.sha256(0, filesize) == "ca4d4c4fc3e5d5cfa922b898f2d7411f03a446dddb139ba45dfd4f8f0018b64f" or
    hash.sha256(0, filesize) == "d43c988d6f9cb355497696b580621fb1bdb7b6ed6d90f97520ecf6da5a1a41ff"
}
