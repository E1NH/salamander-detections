import "hash"
// Salamander CTI  //  https://salacti.com
// Defense and Diplomacy Targeted with HOOKEDGE

rule Salamander_APT28
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT28"
    malware = "HOOKEDGE, HEADLACE"
  condition:
    hash.sha256(0, filesize) == "58cfb8b9fee1caa94813c259901dc1baa96bae7d30d79b79a7d441d0ee4e577e" or
    hash.sha256(0, filesize) == "9097d9cf5e6659e869bf2edf766741b687e3d8570036d853c0ca59ae72f9e9fc" or
    hash.sha256(0, filesize) == "b0f9f0a34ccab1337fbcca24b4f894de8d6d3a6f5db2e0463e2320215e4262e4" or
    hash.sha256(0, filesize) == "df60fa6008b1a0b79c394b42d3ada6bab18b798f3c2ca1530a3e0cb4fbbbe9f6" or
    hash.sha256(0, filesize) == "ed8f20bbab18b39a67e4db9a03090e5af8dc8ec24fe1ddf3521b3f340a8318c1" or
    hash.md5(0, filesize) == "7c103519b975225c26b3c73e56295dde" or
    hash.md5(0, filesize) == "8473a9fb11f822ef738259d4528f9d25" or
    hash.md5(0, filesize) == "b46cbc0a5405703f110218d4ee2e46eb" or
    hash.md5(0, filesize) == "c9f3e6057e1809c10514f6a923a15860" or
    hash.md5(0, filesize) == "eba56e503290204ab2bd77b130b3a1e4" or
    hash.sha1(0, filesize) == "2774b165fab2d2f61a709f4d0411a87fcde920d2" or
    hash.sha1(0, filesize) == "2dc99ef518c3c7fa62f26cd1cc6da9acb376b037" or
    hash.sha1(0, filesize) == "5da5bd587b6039940586a98088f868c31c0b7129" or
    hash.sha1(0, filesize) == "de037b7e5e93ba1f8f6933d479f1216a9f01ecb2" or
    hash.sha1(0, filesize) == "e4b61165be5937987b88352d2f1f8d57def30408" or
    hash.sha256(0, filesize) == "001b57368c10bee9e62374e3b3f232b113eb75a1f198243d43a5bb90e1d0f500" or
    hash.sha256(0, filesize) == "206bd177f3f3b637b0a444ce2dd6d5aaaefc9d66c866ac6ec0c9e946ce140991" or
    hash.sha256(0, filesize) == "231164362b2e4688e5d64ef7154845d655b649470bf995a79107b800ac5663b1" or
    hash.sha256(0, filesize) == "2793e7caba2f9beecd9b01baf41b8cb79f5a1a083ddedc6602ff23996bdc3104" or
    hash.sha256(0, filesize) == "2e320c457658d35a2bb7c420c53bdcc3916f01a7dd4572e5540e8fce923d201b" or
    hash.sha256(0, filesize) == "2e81945ba27108cc613a8aa6aca409ad6f5204e647d08dd9ef7c881c9d28667a" or
    hash.sha256(0, filesize) == "38f0e1e00d5c6d4afd96217556ba1dbe963298be4f9f0890fc1a7618bed009bd" or
    hash.sha256(0, filesize) == "5f2a06bb1d1a210e9c477e4e5db439ce7b11fe9345d39b1b959905ba576a076a" or
    hash.sha256(0, filesize) == "74456a8d6042a4232071bee99e25d23046b993486d6d8a98ab296915bbb53395" or
    hash.sha256(0, filesize) == "7d8e98c0e322110021ae6d89f1a3ea090ef0741cf35b040dd4d0426a502d4845" or
    hash.sha256(0, filesize) == "877648c6ff448aa4efe1e3f004c089411285b8cb4139320e0dbec9d1d1bb3c77" or
    hash.sha256(0, filesize) == "87c15e4cf30098dcbfe9fd506c42896bf6d856aa77a70f312dd621b443b61dc3" or
    hash.sha256(0, filesize) == "8f18e02cbe1fa7abd280d2e070efe7af07e20cfe635f81140d6d347c292f8f44" or
    hash.sha256(0, filesize) == "9c02d5429717001c55420730ee345c172e7ed89df3052b1e32b9bd122fce616d" or
    hash.sha256(0, filesize) == "aebf896b2f60c52af5d38c036159e0243632134643e8ad374cb64ed8cb09f360" or
    hash.sha256(0, filesize) == "b1d037e9ff070d9722b7b289629d9b64a08ec35fd843cc01d37e6db69781ddcb" or
    hash.sha256(0, filesize) == "b8a1494b68617de92a3f58af8ca49dda4e9894f24c718ff3b26897a340e45c80" or
    hash.sha256(0, filesize) == "bfc008f57dca8c6bf341d9d7cf66cdad53faf8b1bcfbeded4593a60f129174b6" or
    hash.sha256(0, filesize) == "c2c9187033d22d7944ea9298461a0ac693ef2774b4ce08b0955d2aba3646fb44" or
    hash.sha256(0, filesize) == "c6db004f2e8ff321d8a0e6d0134f2737d0f6ff79a4627a4b803ef926c107aa00" or
    hash.sha256(0, filesize) == "f611e5415e21f229f75a42011d092e781ffe4118bb70ac95b9d85c41c81ef6ca"
}
