import "hash"
// Salamander CTI  //  https://salacti.com
// A China-Nexus Campaign Against Government Infrastructure

rule Salamander_China_nexus
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "China-nexus"
    malware = "Cobalt Strike"
  condition:
    hash.sha256(0, filesize) == "d7ed70cdd88f6cccbdc0ad6851d7a61b7fce79fdf9c4cd9f9bb375233a96b2dd" or
    hash.md5(0, filesize) == "456233b58bcf8c17ef9ef44b14a966a6" or
    hash.md5(0, filesize) == "71072a8c4adfcde49a4b163959a24283" or
    hash.md5(0, filesize) == "8887c65035893d99996991282553fc19" or
    hash.md5(0, filesize) == "913a572c1bf9da27ee7d21befa3cee0c" or
    hash.sha1(0, filesize) == "9ab45387111475d5cfb77fb4e49eba82bad7ca4d" or
    hash.sha1(0, filesize) == "a24b4bb466324459f40e6adbc5d481ec6cee48ef" or
    hash.sha1(0, filesize) == "b1f71014f4c0e1e61c0b3fe2391a6c6aa03ac3f9" or
    hash.sha1(0, filesize) == "d26f84a768062c52179216bf6ca4c551448890be" or
    hash.sha256(0, filesize) == "00b0cef237d9619c99c5d90cf902ec768c1ecf4f96d542d31dc5afb0b564cb4f" or
    hash.sha256(0, filesize) == "20e1ec6b07abe3b2dd54f7ae4e47dc00afa46de6e6c0ef0239c26c8bae70a43a" or
    hash.sha256(0, filesize) == "2ac6c953d2d36eb7e7e85aa0822a65961071f7801a25118ab42bcfa9693327a1" or
    hash.sha256(0, filesize) == "4738f3559c10f7c62a3be48ec2ce42c584b53d5ffa9e06e6521607a6fdfd535f" or
    hash.sha256(0, filesize) == "66543c4f9f4d610a79efa5e52b9aa90ca41dbfc154418435a2902ac48dad2ee4" or
    hash.sha256(0, filesize) == "75d39860a5c5ce6c26590265102f25c50f91a22b6769d22046759fb3aff8d0a8" or
    hash.sha256(0, filesize) == "9c59a0dadec1f1b73724f3ee4113e4fde696214371b9068fd69774db4cd8b8d2" or
    hash.sha256(0, filesize) == "a4989ae1d598e79a87a9e01d0b5966a25b00b23ca234fbdb52b9df7b29db918a" or
    hash.sha256(0, filesize) == "adde431d5b78b2b2cfb67c5bcd938be6cc466fbb3ac2786cad97b493f6fcfad5" or
    hash.sha256(0, filesize) == "b272e2e4a7c65f2659a8fff8ceec4d9538f74f6dc9bace7d051a4476ba6bc77c" or
    hash.sha256(0, filesize) == "b7486bb7fc5f7e659b40dab3366b576d68db61ca0004de7a1e115eb9b541f19a" or
    hash.sha256(0, filesize) == "b96cdf8bc96c7288af7624974b1a10b7bf16e5ac03ac8493ade20696a906a81a" or
    hash.sha256(0, filesize) == "c0a5374a425ee5030b2219520dfa3a3a51f27d3cc4404b016e695c4450fe3034" or
    hash.sha256(0, filesize) == "c2d0e4dd2f2b3f1d4eb4518984b00ed521c73d1e935780786479db690112ef9c" or
    hash.sha256(0, filesize) == "dc493eb8367b7d68f4d3d9f2a10c495c6a45c33df72fb5a18bdf62b629f69e31" or
    hash.sha256(0, filesize) == "ebc94e24e4df94f988dd0a2275e8a3f1957051814a3c39ec30bfaca2f5ca2607"
}
