import "hash"
// Salamander CTI  //  https://salacti.com
// Introducing CylindricalCanine: The GoldenEyeDog subgroup responsible for the April DigiCert incident

rule Salamander_CylindricalCanine
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "CylindricalCanine"
    malware = "Golden Gh0st Loader, Golden Gh0st RAT, gh0st RAT - S0032, Mydoor, Moudoor, Zhong Stealer"
  condition:
    hash.sha256(0, filesize) == "1abffe97aafe9916b366da57458a78338598cab9742c2d9e03e4ad0ba11f29bf" or
    hash.sha256(0, filesize) == "4eaebd93e23be3427d4c1349d64bef4b5fc455c93aebb9b5b752981e9266488e" or
    hash.sha256(0, filesize) == "dd44dabff536a1aa9b845dd891ad483162d4f28913344c93e5d59f648a186098" or
    hash.md5(0, filesize) == "54def291b6bd573186734895b7ed03b6" or
    hash.md5(0, filesize) == "639b0dd0fe4da3f4743de6347d7d58b7" or
    hash.md5(0, filesize) == "efe7a351491008a2ccb6b5d586904aba" or
    hash.sha1(0, filesize) == "f04ccc9a18dc71ccc4d4b1f651d3d0d2af8ab402" or
    hash.sha1(0, filesize) == "f1888d0b44e5e1d5864ca5a9e93bf65c09411320" or
    hash.sha256(0, filesize) == "2031a71c399563adaf1572e10abb395387eb132208a001c5e140496d7a3e0b26" or
    hash.sha256(0, filesize) == "27b722c66f69e360c4da106daacf3b9eeaabd20634d7e5eff45a28bd70ebfd65" or
    hash.sha256(0, filesize) == "2b0071007c3f5fa8e949a8de53be03e97901dd505694ca939b575a49e4fdbdbb" or
    hash.sha256(0, filesize) == "3313f347e83aaf48ea31fb1d49fc37452f48f81d20a1b93009e2e78385ff4bba" or
    hash.sha256(0, filesize) == "81e276aaa3eb9b3f595663c316b3c6414cc3dde5e6cc3a82856b7276acabb7de" or
    hash.sha256(0, filesize) == "8a913610e905c3dd1f657811ea3b1933471b230f88e1c155616099a03ab0abc0" or
    hash.sha256(0, filesize) == "d1b1938963037aa332591a4c999523a05886d1f62d80e03f0adc22630b8671c4" or
    hash.sha256(0, filesize) == "f67de637fca127212dc60b9a02f74e66dbd602b3b9f6f6e4f2b75614c1f9e944"
}
