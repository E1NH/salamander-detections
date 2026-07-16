import "hash"
// Salamander CTI  //  https://salacti.com
// 11 Malicious NuGet Tools Pose as Game Cheats to Drop a Windows Host-Surveillance Payload

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "pepesoft.exe"
  condition:
    hash.sha256(0, filesize) == "d5385526f2f3e52c7d96087611c6cd4e479bf61828400efdb3ca09406d981609" or
    hash.sha256(0, filesize) == "9a2091e6625fc11cfd8f39c17aa271604e66322ee045028946274b988103e35b" or
    hash.sha256(0, filesize) == "900ddb81d27e03967209fee4d17d13deb68eef0e1f10936eb520ca10575cb49e" or
    hash.sha256(0, filesize) == "ab58a90eb3682c6dc3389cd700a64f68a19c0dac3d0fa8e3df97ae041f96d4e1" or
    hash.sha256(0, filesize) == "e6e1049158ceb1971c61388349c81fa6047a7aecb4ff2089ef54a50dcc35dbc0" or
    hash.sha256(0, filesize) == "d9f7ca9f93a7d188d51db308877b15d0beae932ca0bf4705384fbedf54b454c1" or
    hash.sha256(0, filesize) == "4d13f1136b13c871c65141b77ec7208488334ac4be511800196adcd328666305" or
    hash.sha256(0, filesize) == "011926de3d0cc2b970627b9bf0de003e731f8576602dff756d2ab54a9de61972" or
    hash.sha256(0, filesize) == "79c09e1ffb4804c14ff27d41ec08d4390455c92d65717be0aeeec2697297d76a" or
    hash.sha256(0, filesize) == "5f3a9ebf7039097b3cdbca8609b5b68af07eeb1dbf716ba2817a97fc7c543854" or
    hash.sha256(0, filesize) == "23808e7638f7a00b1ef9b9f4ca524f8a46cf63be6f6b79fec8e4a3fd1cc82a1e" or
    hash.sha256(0, filesize) == "e8c2618565aa31d7ffe909ebc99040bafcc0ea8df7f5d92fa673bb7ffacb14c9" or
    hash.sha256(0, filesize) == "6eefe9d5f030d403c72bd4e4caf5bbb9dbc2bd5e15ebb07de153494f458e5eb9" or
    hash.sha256(0, filesize) == "8ab256dd839aec6638cd46374f4a6664e534b9341bbcdfd9b763e5a27c51ddb7" or
    hash.sha256(0, filesize) == "6c1f828e4d8395dde8293868c65ba8d86b3b9672ebbbb16e932624706d37d832" or
    hash.sha256(0, filesize) == "6cbd4bc491deb11040e2b2f91b0b4e129af551a802fc78cb42e0e985297ef44c" or
    hash.sha256(0, filesize) == "5d9843126db4223dc2a8a9cd4a627286fe1a6345e33b28e9c98b5fe56fe89da6" or
    hash.sha256(0, filesize) == "c9f3e7766dbe728d84a1243447faa5f5eba0645bf13089074d128ea7663e7f5b" or
    hash.sha256(0, filesize) == "a2a5e473dba85959b21b7e8a184bc255d5f2dacdf7411b91d212fb1217d2518b" or
    hash.sha256(0, filesize) == "ba7fc544994f126cb7485ce52d265d2f32e93c4f1ea1fcd6fcdee3918f271979" or
    hash.sha256(0, filesize) == "567952daf0ab7b36b017aac9963791188dea0fbf2e99c7cc6f6652ee540f4840" or
    hash.sha256(0, filesize) == "cc853b3e4504c890d275ac2327f18acd7e4c5b99ca056181f3f5694781f2cf45" or
    hash.sha256(0, filesize) == "476c6f36a22156e53548a87291989a21d6c905dcbd9e1bf68ff5bc12e5c8bb07" or
    hash.sha256(0, filesize) == "774e40046f353e3f916f39e3d13d6499da35705a479cfb89288c21017aaf5461" or
    hash.sha256(0, filesize) == "23e4d8af5425dae022793450190c8d30809b2986dd879eb4bff557cdacf49c86" or
    hash.sha256(0, filesize) == "95577498d23fe750221a5badfc25b5e9f020dcf4d80c79a019b090e3c3b0a32a" or
    hash.sha256(0, filesize) == "2a4fed04d792b9c2fdf9c1456a08ca23eda5fef50c0b409ab294ad489e12d801" or
    hash.sha256(0, filesize) == "7e42d25e707d29d5d185a4c5dc71019f744e88a30b66bbf06949194ff32dbc48" or
    hash.sha256(0, filesize) == "d59e1914d76499fa51bf861f418c84bda0b48913dc39bd2e73756e326e4ccbb0" or
    hash.sha256(0, filesize) == "17b1d836c2f15a97be0350879943b04e14bc076cf09e31df0d73258ee10f7e7c" or
    hash.sha256(0, filesize) == "01d2afea0f2201a3b59765a1a60ba324ff4b8fdd25f23a0e05824b97f195b27c" or
    hash.md5(0, filesize) == "21b4be57bd3743738393f44d9464e212" or
    hash.md5(0, filesize) == "5bd610283d9c4b4ead45ca4f1b35d0f4" or
    hash.md5(0, filesize) == "d6b2c2d2851a63b90e7210a943d0fdf6" or
    hash.sha1(0, filesize) == "642bfeae924b9d4e6ed642b5946ac8e745cfc531"
}
