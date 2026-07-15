import "hash"
// Salamander CTI  //  https://salacti.com
// Update on Attacks by Threat Group APT-C-60 in 2026

rule Salamander_APT_C_60
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT-C-60"
    malware = "SpyGlace"
  condition:
    hash.md5(0, filesize) == "c668ad9966fde17f8ea32339c958b506" or
    hash.sha1(0, filesize) == "5c5059e80d808ef02b3da0435deb143adcadf059" or
    hash.sha256(0, filesize) == "002e1207b96361fc4d53b10621225d61700003241fa38caacb411384b3d51135" or
    hash.sha256(0, filesize) == "0120a6396952aec3f05ec0b0efe25e2a1b73545d55d74a3ac0bcd359d29f52bb" or
    hash.sha256(0, filesize) == "0420fd9e5f9961458604909391fb0f1a353c17c986b55fc5722c1b68e41865df" or
    hash.sha256(0, filesize) == "0bda4beded9c2923fe16f20b7cbd7baf1a5b7078be5cde715592529a974f9bd9" or
    hash.sha256(0, filesize) == "0bf85d9065feb20ee946acf77c985cc7ec78de048ee41d8c5931e0e88873efaa" or
    hash.sha256(0, filesize) == "119ad3dce05b5ef3db5a76655ac050eac51e318f1f31351ac103693a0a849158" or
    hash.sha256(0, filesize) == "131c27c3dce040979044ac1d363050c5d226af76aef1454bbf87c7193f8fc747" or
    hash.sha256(0, filesize) == "131d8f72fde45c5ca1f662c510c3da16fbcd8ff6ef9b9fd893c25a9c8e8ec205" or
    hash.sha256(0, filesize) == "14d799f7897d25f7cfb4d1c86f43c791b6d778d2efd92b5fac4f65fc472bf501" or
    hash.sha256(0, filesize) == "151b2dc70d141c12a33d8e45a80659fc53a71734e27233326bff150ac87744ea" or
    hash.sha256(0, filesize) == "16bdde15cbf9190883c146bab495c8be73daff4fff5ffbf86b4ee46847103fba" or
    hash.sha256(0, filesize) == "18683bba19695d325372d195634afd2f76b14896ba68225ba51ea5a039f2f76d" or
    hash.sha256(0, filesize) == "1aaf59f05bb724d501cc9bcd6642ab8fd7347cf274d46c24719c9dced9b22bea" or
    hash.sha256(0, filesize) == "1ae423e91f6cd679f9ea5be879b07379633b05cd850c37a8a65cdeaf508d097e" or
    hash.sha256(0, filesize) == "1b25c3d56fdb195b427a9c3bfc1f0e98e77a15322e8d3fc53a18edcc4891847f" or
    hash.sha256(0, filesize) == "21ddfbf726caa6d0f32a6bbce8e619f75c81f884bca48564c7a0e5a84bf4bd39" or
    hash.sha256(0, filesize) == "22de84e8f29cba932cf65cf4dc1d333cb8b2e468204f97030712bee32691ac3b" or
    hash.sha256(0, filesize) == "23b37d2ebe683cec3b145b6f2234ee728b99228cf3774399fcfad9502daab9a9" or
    hash.sha256(0, filesize) == "248ded4723e9f5da793e5e42d1ba7c2293dd704718f149b84b3b9b818a1f51db" or
    hash.sha256(0, filesize) == "2952d72ad1d44f3d424600b8fa4076794e2e072ab46936012a5fb872c67ce189" or
    hash.sha256(0, filesize) == "2b650e2e2c46a52378aee70fbaff1ce5e832c759c5f937532047f52500428c4d" or
    hash.sha256(0, filesize) == "2c98781e39a091b370ebd748b495c45752b2c54cdf2c36814358c8c6bd3ae912" or
    hash.sha256(0, filesize) == "2d8def39b76ca17b419e5084832105c0167a171fdcc14eebd0c872ccb7bf9b0c" or
    hash.sha256(0, filesize) == "3b7a80fc62eb8b248fd0be0d94c78f1efe2f510499c68865a6d0c4ead6bc4055" or
    hash.sha256(0, filesize) == "3c509ec732979d8c91009d2c9f898bea81f3fc4064c3c56576257f61f9bfaaee" or
    hash.sha256(0, filesize) == "3e2bc0bd2eb84282086cc5946673b22414a16e982402f1f05ea57059d2962588" or
    hash.sha256(0, filesize) == "3f2f69a8403e6b4e02ebe65448caf6abb8e2fbd1f7636ec71599f2d2d5fac8fb" or
    hash.sha256(0, filesize) == "3f67b777660241a1afc39f2ec388cac933a9eb31b3a34bddd12e39e663f1b566" or
    hash.sha256(0, filesize) == "43d597783af656a35184021f5e20686896463a1712f9216e0217a2ca740e3935" or
    hash.sha256(0, filesize) == "44a4ac119349f525d877728b53fe38453a516881d577679caf08ab69312a695f" or
    hash.sha256(0, filesize) == "45b2ba7c7a39817e1421f2abe2f869fa16af9651a6c863ac59683268fb391fe6" or
    hash.sha256(0, filesize) == "48bb091e0cab562fe094e0ef6a77b434dba97380c09a707220cbd9ca37999484" or
    hash.sha256(0, filesize) == "50ebf107d522326c9a9db8821fe3263aa5136964faaf5dd183657bbb52725f84" or
    hash.sha256(0, filesize) == "5115277eabf2d22d49dcef1e155874387d8e783853bd86debf7ff58588aae35d" or
    hash.sha256(0, filesize) == "5272917261d7091a59e00f9d09cd7eb1d3e111115a5b367f79a66d0d7c7b01f4" or
    hash.sha256(0, filesize) == "555360fb918b959176d669ef0ed40ec0b5ee57005fc625109891a16d02952462" or
    hash.sha256(0, filesize) == "55640ad319208915593db8ad43724dddf6e6e17fc6b0014affa69c90f5cd1eb4" or
    hash.sha256(0, filesize) == "5ab41cf20315d2ea1385967d588159873a65ef5581a0b78de06c0d8617894194" or
    hash.sha256(0, filesize) == "5c3d820e032592f47ffb4850ae0183749199b3e0dca3413cd0c3cb631e322f1b" or
    hash.sha256(0, filesize) == "5e97848bebf521766910d9c8378e98bf7aa1ce4b06aeb6c3f86c31ababbe9663" or
    hash.sha256(0, filesize) == "60972abf5425c191c81bae117f1dedaea13d39bc52f367d5dff9ad1aa4b9c5ca" or
    hash.sha256(0, filesize) == "62a879b0d1c1649cc72b2b6f61a8f6bd888625ce6e8a7aefe0a0461e4f27c525" or
    hash.sha256(0, filesize) == "669002654c264191d4660fbf757860d930175649735f81370b9f1af3658a304c" or
    hash.sha256(0, filesize) == "6b84eab2aac7754b99d04365a83ec374e3cea99cc3223118a5f8fd545a8483e5" or
    hash.sha256(0, filesize) == "6cdc895eda4847f700d6f82fa2e3a8c72c10da1e16455985df855372142ebbd8" or
    hash.sha256(0, filesize) == "71819a1b856b49e7f194ce60468ed8e5ea925c75d01484f4d28ffcf69d480b36" or
    hash.sha256(0, filesize) == "771a47120b935e218322046e838347d722d265b91f1afdef91194a5bec86a97a" or
    hash.sha256(0, filesize) == "78c108be692f1c45ed1da1988e3c5ac792c832a78d0b6e8e6550763156fe8f97" or
    hash.sha256(0, filesize) == "7900c2772680523cadc9fe4e07300d45500191ba64ff5b91573531b133840b14" or
    hash.sha256(0, filesize) == "7aa76237a7686583cc526b9d1a8486a52bd44a448d75ced51e1df4ba29ddb163" or
    hash.sha256(0, filesize) == "7b297f18ece81e87608e158288cc9c06cb9f4a8f1b2d2256aecf7bba8d7be2ab" or
    hash.sha256(0, filesize) == "7c3d0bebd263d3529132f2299de55a7801bf3ff40c833b13838be7a98ea3475e" or
    hash.sha256(0, filesize) == "7d09891e26d56a8bec44c3fe9a5791f3a93e8fa31539951ae6e2c40af83ba42d" or
    hash.sha256(0, filesize) == "8114e3f213713dbbbacafcd0f62884a7826139b434bb3c77eae8dce656477621" or
    hash.sha256(0, filesize) == "83a22d4f61b054bda53a2ea4f506e97d818c7c961d8cd3975c1f2a51443cf95c" or
    hash.sha256(0, filesize) == "843c4dc402e96ed72d7716d980c99e5dfa222a2a322250b7c3755a00d142bc1f" or
    hash.sha256(0, filesize) == "866564bb455bb3c9f3e15cbbc1dcaf75c533a224eb96c4b6d6739e114ee1d065" or
    hash.sha256(0, filesize) == "86ab5161f761822d16637d4d34b84ca6e1f66cea905aa27510620c9cf5f170d8"
}
