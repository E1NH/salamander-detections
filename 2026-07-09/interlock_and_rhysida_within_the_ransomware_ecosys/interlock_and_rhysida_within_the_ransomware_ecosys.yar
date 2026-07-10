import "hash"
// Salamander CTI  //  https://salacti.com
// Interlock and Rhysida within the Ransomware Ecosystem

rule Salamander_Hive0163__Rhysida__Vanilla_Tempest__TAG
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Hive0163, Rhysida, Vanilla Tempest, TAG-124, ITG23"
    malware = "NodeSnake, InterlockRAT, JunkFiction, Supper, Interlock, Rhysida, Broomstick, Endico, Tomb, IceNova, Latrodectus, Gootloader, SocGholish, MintLoader, ModeloRAT, Brave Prince - S0252, Vidar, Dave, SystemBC, Sliver, Berserk Stealer, Mallard, Plus Keylogger, NtlmThief, PortStarter"
  condition:
    hash.md5(0, filesize) == "f0b3e112ce4807a28e2b5d66a840ed7f" or
    hash.sha1(0, filesize) == "54a6743781fd4ceb720331fce92f16186931192d" or
    hash.sha256(0, filesize) == "333903c7d22a27098e45fc64b77a264aa220605cfbd3e329c200d7e4b42c881c" or
    hash.md5(0, filesize) == "edbf152ed9ac79e5d9e0111d1071af48" or
    hash.sha1(0, filesize) == "b0cfa2089802634ffb8c77962cdb18317a6332d4" or
    hash.sha256(0, filesize) == "64a0ab00d90682b1807c5d7da1a4ae67cde4c5757fc7d995d8f126f0ec8ae983" or
    hash.sha256(0, filesize) == "c9920e995fbc98cd3883ef4c4520300d5e82bab5d2a5c781e9e9fe694a43e82f" or
    hash.sha256(0, filesize) == "43f4ca1c7474c0476a42d937dc4af01c8ccfc20331baa0465ac0f3408f52b2e2" or
    hash.sha256(0, filesize) == "7890b116d13a52efe696ce1e2c0ed83029775cf4bea836ce551e71d222ee116f" or
    hash.sha256(0, filesize) == "f962e15c6efebb3c29fe399bb168066042b616affddd83f72570c979184ec55c" or
    hash.sha256(0, filesize) == "28a9982cf2b4fc53a1545b6ed0d0c1788ca9369a847750f5652ffa0ca7f7b7d3" or
    hash.md5(0, filesize) == "2b2e657ae1bc2fdcdfe5201a8e0e5224" or
    hash.sha1(0, filesize) == "8bd16897409ae5d5667c345276d2532f493c0f98" or
    hash.md5(0, filesize) == "259fd28f9e66159d5a30b86688fec184" or
    hash.md5(0, filesize) == "42a99a5effdc1d02f6b622537de881e1" or
    hash.sha1(0, filesize) == "3e62797fd746ce9bd5d49cb833b7d9ac62d6b7a2" or
    hash.sha1(0, filesize) == "442af2726e22f512b49f67bcdbf7c0d1e806aa8b" or
    hash.sha256(0, filesize) == "16474e9e4773fbc1e0b48a5025fad31b7f084b1beffb9a42687b4d01979885fe" or
    hash.sha256(0, filesize) == "2528df60e55f210a6396dd7740d76afe30d5e9e8684a5b8a02a63bdcb5041bfc" or
    hash.sha256(0, filesize) == "4e4a3751581252e210f6f45881d778d1f482146f92dc790504bfbcd2bdfa0129" or
    hash.sha256(0, filesize) == "6190923b28679eb8230010aff9b1d1a4184e8697540cc021a5be38126f3f6d99" or
    hash.sha256(0, filesize) == "72bed9b26a7747252156b65d24a9a737d70b9bf6aca069c514c1c7b9e04ef9b6" or
    hash.sha256(0, filesize) == "b659389cde06f5e01e592dca458fe1be07a302c40dc2a820c7f76d4ee788bad3" or
    hash.md5(0, filesize) == "16afa928cd820a572bd47e798f481c46" or
    hash.sha1(0, filesize) == "273962821f14982ead6c10823587fd39e89cf2fc" or
    hash.md5(0, filesize) == "4482fdd6d9269d3b748233ff4a87e9e2" or
    hash.md5(0, filesize) == "e6bff27adbbcfe6b71ac8fad79b8297f" or
    hash.sha1(0, filesize) == "86edacec5be6df1bb5431e228e688ac3936df5b8" or
    hash.sha1(0, filesize) == "8819a011ff38b0b0587f0cae0f3572502ec3c82d" or
    hash.md5(0, filesize) == "aecc447b2b69af35e20c3ea91e21e853" or
    hash.sha1(0, filesize) == "29765840a9897f93ea3bf07ef59ffa8ae8cd5f14" or
    hash.sha256(0, filesize) == "55a02d14de13134e77eb9cc787ac622791b38b74931d1588bb5750b06951c8c0" or
    hash.sha256(0, filesize) == "f34cfdc950124d26b4f2f99b192a4ab7a4163af3143c3b18bc2271ca08d6c899" or
    hash.md5(0, filesize) == "366a9c89b9769117b5014a918d222456" or
    hash.sha1(0, filesize) == "c524749d590c5057642f72b583e2336b6e80d0ff" or
    hash.sha256(0, filesize) == "c15f44d6abb3a2a882ffdc9b90f7bb5d1a233c0aa183eb765aa8bfba5832c8c6" or
    hash.md5(0, filesize) == "273ce734daab80ddc2850b4975ac3c7b" or
    hash.sha1(0, filesize) == "794a0b6f21d80a426ac33a706a962b66a6cc0492" or
    hash.md5(0, filesize) == "583d4a295c4ff7ae8bd4cb2085a39934" or
    hash.sha1(0, filesize) == "b0b63051f231bc2dcb67bec9ac8702177678fa39" or
    hash.sha256(0, filesize) == "7ed805c5fc3bd0a4eab3d523483a9cc83b8768ff667875f2318f3bfa4ef68fe2" or
    hash.md5(0, filesize) == "b2b03dfcdc2e59d81e99d20c15919a13" or
    hash.md5(0, filesize) == "422755116ab311b473dd38ec88f129d9"
}
