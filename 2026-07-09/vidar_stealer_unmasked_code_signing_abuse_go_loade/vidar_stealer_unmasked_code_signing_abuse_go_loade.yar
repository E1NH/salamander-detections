import "hash"
// Salamander CTI  //  https://salacti.com
// Vidar Stealer Unmasked: Code Signing Abuse, Go Loaders and File Inflation

rule Salamander_X3D_MINER
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "X3D MINER"
    malware = "ClearFake, LummaStealer, RemusStealer, Smoke Loader, Vidar"
  condition:
    hash.md5(0, filesize) == "d42595b695fc008ef2c56aabd8efd68e" or
    hash.md5(0, filesize) == "1aae8bf580c846f39c71c05898e57e88" or
    hash.md5(0, filesize) == "d8b31f8c03e0c76ff245ed05a15ffe6c" or
    hash.sha256(0, filesize) == "03e6f4f49cec3af38bbec9ed64c195c7a85a630ec989efb3669f04a2993c1dd7" or
    hash.sha256(0, filesize) == "6b7ff061eebeb9ead8812c410247768a7ba90786aeeb1bafa6412cc5b08237b5" or
    hash.sha256(0, filesize) == "b830f043076a12748b6a2dc0810ece85439ee77434d991ae7d84201b09ead756" or
    hash.sha256(0, filesize) == "68ced9d7c1b1ff8ffb5f56c7d3f849d4fd16a1b95324426811424b40043d6d25" or
    hash.sha256(0, filesize) == "b9b6893fa6b04ee8daa29e515c08239ac5204af1a1fa2bc10006eede1b41329b" or
    hash.sha256(0, filesize) == "d6446f2803444bd2200d48a01a9ad7d487e67e8e831c9cd13f89cbfec17fd4e2" or
    hash.sha256(0, filesize) == "74df77b6a83d89fa137fd285a2efde36b1d62c00b3be81cc93df7d1e6e94837b" or
    hash.sha256(0, filesize) == "b8b5f6991a3a61083461d5269245bebf28b90934c328848ba8c1e084a5a6216c" or
    hash.sha256(0, filesize) == "95cd48130247525d8a7e966bd3fa07e9d6c39ebbe3058ecccb336f66bb8e3d1e" or
    hash.sha256(0, filesize) == "613e5314a7ded3155cdec49fd34e852e181f4651d78bd8bf3adad2f4dbf22b0d" or
    hash.sha256(0, filesize) == "8dbcde2a28a0b3de201214d7e3bd43acc97561924daa247c05c4b0536d42be85" or
    hash.sha256(0, filesize) == "634e89d8592d7c9e2bc1c098217a813947b44a4f80bc569e9a15c1e8b0864b91" or
    hash.sha256(0, filesize) == "6d49233b1fca22f3823e856e4c16749e9c45f384ea57055fead16df35b217226" or
    hash.md5(0, filesize) == "8cb8301f664e1e42dee8b7032fa321fc" or
    hash.sha1(0, filesize) == "f732e938a8fda479886576df82c611f9540db42c" or
    hash.sha256(0, filesize) == "3e906ae47e9836a591f44d4b743e961d634a404fa8fd8bfae64f1d54c853be2b" or
    hash.sha256(0, filesize) == "b6912c23cccc4b0964d55608916297f6978f0b38c80a4beac472004a786fcef7" or
    hash.md5(0, filesize) == "03222c6ca2f60f70b95e454141ce8e25" or
    hash.md5(0, filesize) == "033a49eb29d1ca3979757f3263ff6417" or
    hash.md5(0, filesize) == "056207e13f91698b94ead7c21cc5a1ba" or
    hash.md5(0, filesize) == "3c5300ebbc140ec500d5ddc886b95cd5" or
    hash.md5(0, filesize) == "3e177cc39048ad17dce44452666bba0e" or
    hash.md5(0, filesize) == "4d40d9c6445cb096f24bbca6862042a7" or
    hash.md5(0, filesize) == "5132da5f4c7c4693c7bdfbda5c047300" or
    hash.md5(0, filesize) == "55e7443b66c9c626abe71551233e0a30" or
    hash.md5(0, filesize) == "655393e472be5409bc0ff521aa1662de" or
    hash.md5(0, filesize) == "6695ae857e67b6283d49c6531a253db6" or
    hash.md5(0, filesize) == "684c8447df60b13bc258a33ed636ce93" or
    hash.md5(0, filesize) == "70f7dc41628613af7bb16490ca6c8510" or
    hash.md5(0, filesize) == "72633fc47f89679472f058be0177a494" or
    hash.md5(0, filesize) == "874df2d775a5eb406bc9d2c8811ce8c7" or
    hash.md5(0, filesize) == "8c2b728e57531e24813e628cfba3f1c5" or
    hash.md5(0, filesize) == "8ff9f6c05dfde0ee639c36cb53cb29a5" or
    hash.md5(0, filesize) == "92926805ef829d33fb290c44a4f7dd26" or
    hash.md5(0, filesize) == "96bc7cf49632b140a196c50a8f0e43cc" or
    hash.md5(0, filesize) == "99775c9078774ed124e37d089334de5b" or
    hash.md5(0, filesize) == "a30418484257d640e670af047d8f7bca" or
    hash.md5(0, filesize) == "a4d12dfb189162105608636e63e5b2c5" or
    hash.md5(0, filesize) == "c10333c92889b65c3590ef2b3819b420" or
    hash.md5(0, filesize) == "c7abe29809cd243a2dfe4d8f1c004228" or
    hash.md5(0, filesize) == "ce0f23981ef41b8be349b32e7bfb70ad" or
    hash.md5(0, filesize) == "dc17d8e9f92d83ec92f9789f0f0d720d" or
    hash.md5(0, filesize) == "de3c6dc21330f6c501ada99d2206e27f" or
    hash.md5(0, filesize) == "eca863e5c96a59267878e4f9a7e32b46" or
    hash.md5(0, filesize) == "f38a0009fac3944821ff2a2f021ab413" or
    hash.sha1(0, filesize) == "1fe42725e5471a3f365a1180f798946643924d3b" or
    hash.sha1(0, filesize) == "31538b5e35ba2ffbe3f67810c773c14c1617ba00" or
    hash.sha1(0, filesize) == "489e62c252832cdb5cacf35bd6b193aeecc816c8" or
    hash.sha1(0, filesize) == "4bd372ca29c2efa50740c9e38c72768e4521b8de" or
    hash.sha1(0, filesize) == "5131e320f190f796f73a4553d30ce24586c27976" or
    hash.sha1(0, filesize) == "58277a661d553f4dcbd8a6dce9f6a29019e3cf4b" or
    hash.sha1(0, filesize) == "5f04874433e330d74aa7c7247b543e34ca924f64" or
    hash.sha1(0, filesize) == "65f5161364a1a759cd48d3e3ae87231ef8665d26"
}
