import "hash"
// Salamander CTI  //  https://salacti.com
// Cloud Atlas activity in the second half of 2025 and early 2026: new tools and a new payload

rule Salamander_Inception_Framework
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Inception Framework"
    malware = "PowerCloud, VBCloud, PowerShower - S0441, ReverseSocks, PhantomHeart, ValleyRAT, ABCDoor, NetSupport RAT"
  condition:
    hash.md5(0, filesize) == "0320dd389fdbab25d46792bd2817675e" or
    hash.md5(0, filesize) == "0577db70844e88b32b954906e2f20798" or
    hash.md5(0, filesize) == "0857c84b62289a1a9f29e19244e9a499" or
    hash.md5(0, filesize) == "097ca205ad9e3b72018750280904718c" or
    hash.md5(0, filesize) == "0c514e137860f489e3801213460ef938" or
    hash.md5(0, filesize) == "116f59e70a9df97f4adaea71eecb1e9a" or
    hash.md5(0, filesize) == "1a11b26dd0261ef27a112ce8b361c247" or
    hash.md5(0, filesize) == "1b39e86eb772a0e40060b672b7f574f1" or
    hash.md5(0, filesize) == "1d401d6e6fc0b00aaa2c65a0ac0cfd6b" or
    hash.md5(0, filesize) == "2042eb5d52f0b535a1ce6b6f954c8c2b" or
    hash.md5(0, filesize) == "216cb7f31d383c0dd892b284df05a495" or
    hash.md5(0, filesize) == "25c8ed0511375dca57ef136ac3fa0cca" or
    hash.md5(0, filesize) == "28ecf8fb6719e14231b94b4d37629b0e" or
    hash.md5(0, filesize) == "2aa1e9765ef6b00b94a9b6be0041436a" or
    hash.md5(0, filesize) == "2b4ba4facf8c299749771a3a4369782e" or
    hash.md5(0, filesize) == "2cabb721681455dae1b6a26709def453" or
    hash.md5(0, filesize) == "344ca9ea07cd4ac90ef27f8890d4ec05" or
    hash.md5(0, filesize) == "36120f5e9411bcbac7104ef3fa964ed2" or
    hash.md5(0, filesize) == "369b75bdcded16469ede7ab8bedcfae1" or
    hash.md5(0, filesize) == "38fa4306fa4406ba31cf171af4d36e34" or
    hash.md5(0, filesize) == "3c75cedb1196df5eab91f31411ed4b33" or
    hash.md5(0, filesize) == "3e6e9df00a764b348ec611ee8504aca0" or
    hash.md5(0, filesize) == "40a562b8600f843b717bc5951b2e3c29" or
    hash.md5(0, filesize) == "42ac350bfbc5b4eb0fedba16c81919c7" or
    hash.md5(0, filesize) == "493b901d1b33eb577db64aadd948f9ce" or
    hash.md5(0, filesize) == "5000a353399500bc78381dc95b6ed2dc" or
    hash.md5(0, filesize) == "50568b1f9335a7e3ba4e5df035a8fb86" or
    hash.md5(0, filesize) == "51f7f794ed43fb90d0f8ebbb5effe628" or
    hash.md5(0, filesize) == "5329f7bff9d0d5db28821b86c26d628f" or
    hash.md5(0, filesize) == "5339d1a666f3e40fe756505cf1d87d4b" or
    hash.md5(0, filesize) == "579a9952d31cad801a3988dbe7914ce7" or
    hash.md5(0, filesize) == "63b6be9ae8d8024a40b200cccb438f1d" or
    hash.md5(0, filesize) == "67d7e3aeeb673bf60c59361c12a4ed81" or
    hash.md5(0, filesize) == "69121c36eb8bf77962dca825fcffd873" or
    hash.md5(0, filesize) == "6aa586bcc45ca2e92a4f0ef47e086fa1" or
    hash.md5(0, filesize) == "6d7b2d1172bbdb7340972d844f6f0717" or
    hash.md5(0, filesize) == "7242ac065b50bcde9308756b49dbadcb" or
    hash.md5(0, filesize) == "7a95360b7e0eb5b107a3d231abbc541a" or
    hash.md5(0, filesize) == "7f776ad200287d6de14a29158c457179" or
    hash.md5(0, filesize) == "8158552950d2e13b075001ce0c52aa97" or
    hash.md5(0, filesize) == "83edde9f7eeefac0363413972f35572b" or
    hash.md5(0, filesize) == "867b634588c0fd6b26684d502c15ab03" or
    hash.md5(0, filesize) == "89572f0ed20791a5ac9fc4267d67ccb0" or
    hash.md5(0, filesize) == "9769f43b9de8d19e803263267fa6d62e" or
    hash.md5(0, filesize) == "9bd788f285e32a05e6591d1eb36ebffc" or
    hash.md5(0, filesize) == "9eaae9491f6a50d6df0be393734a44cb" or
    hash.md5(0, filesize) == "a632858f14b36f03d0f213f5f5d6bff2" or
    hash.md5(0, filesize) == "a75dbed984963b9ab21309c5b2f8fd9b" or
    hash.md5(0, filesize) == "b4e183627b7399006c1bc47b3711e419" or
    hash.md5(0, filesize) == "b6aae073e7bfebf4d643c2bbeb5c02e1" or
    hash.md5(0, filesize) == "b8c753dd254509fba5077ffd5067eab0" or
    hash.md5(0, filesize) == "ba9ce06641067742f2afc9691faff1dc" or
    hash.md5(0, filesize) == "bbf1fa694122e07635deeac11ad712f8" or
    hash.md5(0, filesize) == "bc3739dec8cd8f54f3f60a85f3ed600e"
}
