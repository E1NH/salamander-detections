import "hash"
// Salamander CTI  //  https://salacti.com
// ScreenConnect RMM Abuse, Cloudflare Tunnels, and Trusted Software Lures Threat Intelligence, Threat Research, Threat Security

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "ConnectWise, NetWire RC, Unknown malware"
  condition:
    hash.sha256(0, filesize) == "9161a8f7f07741db06b9f9a87b6ec7f277faf2ae3a3a661d6eb09cec4e12b920" or
    hash.sha256(0, filesize) == "dc8b056dd6eb75df21e9721ac2e340f91bb5e94d5a6ff412d7d0c7539e0f06e2" or
    hash.sha256(0, filesize) == "433b61c29aefaa5b55fe78063e6ad8597d3835f36e1242d5402ab23e6dc61194" or
    hash.sha256(0, filesize) == "8e87a734daddd95322b3f18f71eb9275219e244aac4f62b8dc6da6e2e91525e9" or
    hash.sha256(0, filesize) == "3cd9b7d583442963261f9985128042bf45d25482efcbf903c9248837cb0d744b" or
    hash.sha256(0, filesize) == "dd23012b4dc29cf7901185ae4fb2d507e737e9ea4d467846eafd6a86b26486bf" or
    hash.sha256(0, filesize) == "aa84e2ac68f7fc18f4927b89be7b4a7739f2eaf099e489aa0f65c1d3913ce62a" or
    hash.md5(0, filesize) == "3d4d54fb1aaa70005f040558b5d4cd0c" or
    hash.sha1(0, filesize) == "5731b2f26146fe379f27bbfc5608f4e9ab11a9d3" or
    hash.sha256(0, filesize) == "01e4cb3c60fa50b2927daa11f25a3c412549680406fc121a3d1870a9a33f5d38" or
    hash.sha256(0, filesize) == "9d9f3fa5aaf6bc91091873bd7ee04f0cc23e8709e4ad20c61d2779ff1a43c4b4" or
    hash.md5(0, filesize) == "04ec5209d922b98a947fea48c73ecaa8" or
    hash.md5(0, filesize) == "2f1e4fd2937ccf825a555204b1741f89" or
    hash.md5(0, filesize) == "37da3d949d76c4867c6e8812f2c38f94" or
    hash.md5(0, filesize) == "3cbf062f600bb6c64849f726566557bc" or
    hash.md5(0, filesize) == "57d20ed65870aa249ca374142d763d13" or
    hash.md5(0, filesize) == "690401ed2497ad939e05e0bddfd13dbe" or
    hash.md5(0, filesize) == "73167f265dfbd888e514a3730228d82f" or
    hash.md5(0, filesize) == "86db42b1595d14e0f5bd9816e42423cc" or
    hash.md5(0, filesize) == "b09c029c6f88a6dad8ef690f9c42f2a5" or
    hash.md5(0, filesize) == "b62119f0ae9ad41612f252dd703799d4" or
    hash.md5(0, filesize) == "e9174663dd353d0faf56f005cf30a652" or
    hash.md5(0, filesize) == "f2d291955c241b3967e636c03cf28c7e" or
    hash.sha1(0, filesize) == "19e06d1bf248d1b1ad0d4a1fca8b4dde4733ca43" or
    hash.sha1(0, filesize) == "2c32f560af970493724544b19b05363db6e36d25" or
    hash.sha1(0, filesize) == "2d8faea3e5170802ff2212f862fd5ef1528289ae" or
    hash.sha1(0, filesize) == "4e3422e4848147d648c5e82dfeb163035a10bf26" or
    hash.sha1(0, filesize) == "7618dd88cf6a07df1c64ce71dabc1a8167aefcc6" or
    hash.sha1(0, filesize) == "897a9a38ebc67beb0775184520c8ce3b0bec04e5" or
    hash.sha1(0, filesize) == "923a3c6a7006d0e0fde4deadec5a9cd0b075d122" or
    hash.sha1(0, filesize) == "a54e21752a34a4663cef87b75efe74be139a2c8e" or
    hash.sha1(0, filesize) == "a83a5e93cfb4d1fd65054017abfb7827b48f2e5a" or
    hash.sha1(0, filesize) == "e30f1c194b0c850eb79b4bc39084c75b6aea423b" or
    hash.sha1(0, filesize) == "ea37f1e3004a5c20af5802c35eb2275594db9c59" or
    hash.sha1(0, filesize) == "f67016820b113661570f3cee5c070d84bc1b534d" or
    hash.sha256(0, filesize) == "2423decbfcf820f41bc356547e4e18e61d60c9829421d7121c374dcef88577f7" or
    hash.sha256(0, filesize) == "31260c37cc442719ac84540f4159dd9d4738575d2ab05e92c751a9b4b5f9b91b" or
    hash.sha256(0, filesize) == "35be1b070f06eb313c3cb818c74aa0a9c2d9f39a05621dac4de6cff6067a5d12" or
    hash.sha256(0, filesize) == "371166ebd83e8318b49ba71321396524fbca7dc42fe1ca4badda8af794bf5a59" or
    hash.sha256(0, filesize) == "5253e66f1f493c4e13539749f1aa86fd0c61e3072900fec29a44ba046a6d97e2" or
    hash.sha256(0, filesize) == "60c730addd2a15e4213a1d37f55186686976de73a106317b5a258fe0121cfd5c" or
    hash.sha256(0, filesize) == "639430a33c0ecdf5a134501788a3a40f065ae4232efc66e1b82eca2b355e0606" or
    hash.sha256(0, filesize) == "63c46b3c090a4b1efef146f2f1efc4f93d44f21db21d7825f43e02c3c5c89de6" or
    hash.sha256(0, filesize) == "873011c181d00709fdf66f32bb3cca0c5ff3147d00ef818fef72987a6773ea66" or
    hash.sha256(0, filesize) == "aefac65c42c0c72ed3e08b32774fa1b902f4fd1d53de189d50f38130cc357764" or
    hash.sha256(0, filesize) == "c8695906dcefc64becb3123fa0a8058278c8c2f9c86130956b6b10d49c1a35dc"
}
