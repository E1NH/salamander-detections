import "hash"
// Salamander CTI  //  https://salacti.com
// From poisoned search results to GPU mining: A cryptojacking campaign abusing ScreenConnect and Microsoft .NET utilities

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "SimpleRunPE, RuntimeHost"
  condition:
    hash.sha256(0, filesize) == "1b2555b09ac62164638f47c8272beb6b0f97186e37d3a54cb84c723ff7a2eee5" or
    hash.md5(0, filesize) == "4125681f9276487f4318c7ce9c8b6786" or
    hash.md5(0, filesize) == "512b49f441765698c679b5da5f0cc868" or
    hash.md5(0, filesize) == "56b75638beabd690f38de434f7efd623" or
    hash.md5(0, filesize) == "661d4551df34661f3ffc565e2f4ecdbc" or
    hash.md5(0, filesize) == "d58ce78503c60c19926ed642f0eb9d53" or
    hash.sha1(0, filesize) == "017830597704acd90fb171f3025bc6f28745da57" or
    hash.sha1(0, filesize) == "62d5e9ed6c1444469e4b89f3ca6c2047a5e8eb98" or
    hash.sha1(0, filesize) == "bbeaac7ef00268bd5cc583e26624e760085581dc" or
    hash.sha1(0, filesize) == "c27a1688fa5a4ec9497da0fc9bd88c8b362234c5" or
    hash.sha1(0, filesize) == "f9ea4f4b636614226579ac6cbfc8abe21539a8da" or
    hash.sha256(0, filesize) == "062bb28765fbaa11f8cc341fa16e2c7f942a122d929cb41f4a0f755b4429f246" or
    hash.sha256(0, filesize) == "16562974deec80e41ef57a71a6de8c03ceb393005fb1432f8d9d82c61294ef8c" or
    hash.sha256(0, filesize) == "2ee93ccbcd49ed94c65dcf52e7dcb8f0fa0a443ca24c0e0c7f79152efba657b7" or
    hash.sha256(0, filesize) == "69077fcf940fc5852fb32beed15636756ebc04ac971b7ed71d36251e7ea70a20" or
    hash.sha256(0, filesize) == "7035c2abeb617e828dfda1b119b8544fa9ae15a1d263d18bc5506acaf381f496" or
    hash.sha256(0, filesize) == "9ff07c9fafa9c03fdf69e4abf6806aa7c938b5480e7e258f227db0719ecd6386" or
    hash.sha256(0, filesize) == "a460d00ef93c8ce70d32e48e55781af66a53328fc2dde45519be196c265de074" or
    hash.sha256(0, filesize) == "c7425fbe6c3a4937934215c54027d4b67202d12ab490682fae03498870d66d06" or
    hash.sha256(0, filesize) == "cf3f8160eb5a5580e0c35054847e3ac4d01e9fe74fab8bc12bf6e8a40bf696b2" or
    hash.sha256(0, filesize) == "db2d33c4e6e4a5c2263b56e8303c343305a94dde1fc2968304ba260acbbd9f9f" or
    hash.sha256(0, filesize) == "e021662a652ba95c8778b991056696ab3c9b0f60d5e23b1e6cf73c3847db6610"
}
