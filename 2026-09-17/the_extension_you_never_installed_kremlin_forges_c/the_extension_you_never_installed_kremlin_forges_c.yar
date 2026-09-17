import "hash"
// Salamander CTI  //  https://salacti.com
// The extension you never installed: KREMLIN forges Chrome's own integrity checks to steal banking sessions

rule Salamander_REF9334
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "REF9334"
    malware = "QuasarRAT"
  condition:
    hash.sha1(0, filesize) == "00ea1da4192a2030f9ae023de3b3143ed647bbab" or
    hash.md5(0, filesize) == "2a3ff8f8ea94d4052fe2a7314c4098aa" or
    hash.md5(0, filesize) == "4bc008f4b8da0dd90d282f50030ac78e" or
    hash.sha1(0, filesize) == "11306e7cc9aa68fddb63c766d2606d46181af38c" or
    hash.sha1(0, filesize) == "1c5454be00f4c3c5aed4a8a54bf81c83e84953a3" or
    hash.sha1(0, filesize) == "1df5de857b627b171586b4b0ac800e285faa0c44" or
    hash.sha1(0, filesize) == "2ae7494b60277582bd380bc4195964128341f314" or
    hash.sha1(0, filesize) == "532511730d540422157dc4284f400b5cc83edeb5" or
    hash.sha1(0, filesize) == "6bfef63fd12701f125e49b7d17388e6502b6c090" or
    hash.sha1(0, filesize) == "6f7e7a6d99270b2ff330dd0c9707b3b772301104" or
    hash.sha1(0, filesize) == "728601a30d22a2ad8514f366cc9cc9d829e9f10a" or
    hash.sha1(0, filesize) == "754bf10bc98df84cf6d7ffbf19138805642b1979" or
    hash.sha1(0, filesize) == "b9c5941aab2889700377dc9d52130d2dcf407146" or
    hash.sha1(0, filesize) == "c332e3b49bb9d68e6fc7e9df933c5ba144cce3f8" or
    hash.sha1(0, filesize) == "c61bab62a306d5fdb51a991a017fa351186b664b" or
    hash.sha1(0, filesize) == "fbc6a7525ae1e80342ecf0539026f2375b97b03d" or
    hash.sha256(0, filesize) == "12a2974fe4af869fefb66886b4a2a6f34d358a54038c3424635fee5e5fae111e" or
    hash.sha256(0, filesize) == "598764b174f35ca76586bd0036a3caf87538aec52a1f95cf1c4ce25e027cf71f" or
    hash.sha256(0, filesize) == "62e0383b93de31204574ab52d136c58469e710ce38d2d7f061438ab5abbd76f7" or
    hash.md5(0, filesize) == "1440e142dcf7f00c6385de1ca910210f" or
    hash.sha1(0, filesize) == "902f4f7da9a9fb50ed424915b912a24870a9b854" or
    hash.sha256(0, filesize) == "5df7a18c5674abbab89a53d3398c3398b800b14f8ff08488d89407402325f75a" or
    hash.md5(0, filesize) == "01cf7d7e2e057c95e861a95cbfec6221" or
    hash.sha1(0, filesize) == "c14ad7985e4720a3ba050e93a10103385c5c8d70" or
    hash.sha256(0, filesize) == "f3e081a4b2e4302d3b14e5f16aca269ea93aa5cb816bb7ac2a8e4f51a80f0fde" or
    hash.md5(0, filesize) == "1cd3e8f70cc250246727cbf7fd658296" or
    hash.md5(0, filesize) == "201e6bc16c72f26272ea9541aee5253e" or
    hash.md5(0, filesize) == "88b7d0709ec330cf876fa9215e2017e7" or
    hash.md5(0, filesize) == "948af63e23e0653dd2c77e900c85eccb" or
    hash.md5(0, filesize) == "d3b595c6ae7f8dd98f83a588add1bc19" or
    hash.sha1(0, filesize) == "118c7645045c5a8f77a964c61213ddbc8e079e81" or
    hash.sha1(0, filesize) == "4f866c7f07e9069f530e7bc549b2ced9efffd1eb" or
    hash.sha1(0, filesize) == "787bb9ccc9644732c5d37e86d21bc8ebbb8b4478" or
    hash.sha1(0, filesize) == "8b299fa28ef88ecde317b833c8bb450e23615559" or
    hash.sha1(0, filesize) == "db5b2f08fb76df5223b489997be3d4b82ee299e9" or
    hash.sha256(0, filesize) == "2a45e65d67e3e6a40c91115a5a9d0ab482f88b206735e1391a351d376d0934f2" or
    hash.sha256(0, filesize) == "3e10724585ae86c92b7504014a540d3a97003c7120151db479445b0bc25b01d3" or
    hash.sha256(0, filesize) == "75d5e6bba3672f8e14509ae1c3eccf41986f40feb749279a79d3d791920bf2aa" or
    hash.sha256(0, filesize) == "de5ddf293b2218028988593a61ac8d5faf11605dc0f616c9a2e4858c127f8775" or
    hash.sha256(0, filesize) == "e582390605a848286e4340ad14f4b075abeefdfe11e747f3e879967f7fad744a" or
    hash.md5(0, filesize) == "f9e95a1e1fa3f3aebfc802c6c8e6a2eb"
}
