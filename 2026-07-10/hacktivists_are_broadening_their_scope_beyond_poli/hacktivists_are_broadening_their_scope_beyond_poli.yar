import "hash"
// Salamander CTI  //  https://salacti.com
// Hacktivists are broadening their scope beyond political motivation

rule Salamander_4BID
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "4BID"
    malware = "BlackReaperRAT, Warp RAT, Sliver, Havoc, Mythic Apollo, AdaptixC2, BlackSalt, ClearWater, Blackout Locker, GhostDriver, ValleyRAT, ABCDoor"
  condition:
    hash.md5(0, filesize) == "008cd423ca45134d3343f66cced1d104" or
    hash.md5(0, filesize) == "038cab0c60c53cf12f048272014024c0" or
    hash.md5(0, filesize) == "06bed0a0906e52c764b3b7016d6a4428" or
    hash.md5(0, filesize) == "08c069f133ac27cbc02a0ed79e4e87ba" or
    hash.md5(0, filesize) == "09d0517a1f69feff8186655ae3b567e0" or
    hash.md5(0, filesize) == "0b1870d57221eec6f3bbef648e71a724" or
    hash.md5(0, filesize) == "0c32bfdf83ecebe3a1399d261dc8ff57" or
    hash.md5(0, filesize) == "10824d14c814524155f2b529cf5fee43" or
    hash.md5(0, filesize) == "129225b3e93c17f131bcc2a982ffb09a" or
    hash.md5(0, filesize) == "1344e6bc51cea35befb4adff7a25899b" or
    hash.md5(0, filesize) == "1742a9fa35e253614b76ac0f687ba02e" or
    hash.md5(0, filesize) == "1c0924f5711a24821921de5ad822213b" or
    hash.md5(0, filesize) == "1d09499cb2d7d70df903b60602a58887" or
    hash.md5(0, filesize) == "1e1edf879b2dc6c9892a22bfa5985db1" or
    hash.md5(0, filesize) == "1ff222457f5e0e32adfa8341f260dde7" or
    hash.md5(0, filesize) == "242038139842ec79ec1044c64eb0804a" or
    hash.md5(0, filesize) == "26100db3f56880110a92a2b4742d6eaf" or
    hash.md5(0, filesize) == "2d5533fb65ebb50a5a5fd53e62d73b9a" or
    hash.md5(0, filesize) == "2db94ee3ec69988588702bd77999a5d4" or
    hash.md5(0, filesize) == "2f40bcee90abed0898e92521da17e52d" or
    hash.md5(0, filesize) == "36b3be503c6e34613ff50cb28e0f3ddb" or
    hash.md5(0, filesize) == "389a1bbdbf5c91bd1c179227f5ae0923" or
    hash.md5(0, filesize) == "3a9b0875fc692944c180b165a83a0d17" or
    hash.md5(0, filesize) == "3b974ff986445e5944c51179d19bd6be" or
    hash.md5(0, filesize) == "3d9cbc944f9a9e127550ffb4e8394965" or
    hash.md5(0, filesize) == "3ee38b944e5c83922f99641846f7db0c" or
    hash.md5(0, filesize) == "4c8a0531653b5398a35c6b1b80ff1350" or
    hash.md5(0, filesize) == "5398b7eaa94f0ee570b1c5642b559047" or
    hash.md5(0, filesize) == "53ba13cc6066adfd67f8098c0a5b8dde" or
    hash.md5(0, filesize) == "54a308f734095d54ae0e1c86c849a2d8" or
    hash.md5(0, filesize) == "555a6722436d7cf7de396e0c57d32a27" or
    hash.md5(0, filesize) == "56be07e46fd452315008ed246ebbf52b" or
    hash.md5(0, filesize) == "56d1de3159adbfda20aca593c99901f9" or
    hash.md5(0, filesize) == "579e8bbd6a5bcca89b5acd6fb5db32db" or
    hash.md5(0, filesize) == "5e81f72614db42615489266be11b1d09" or
    hash.md5(0, filesize) == "60f8b115aec8a13b0069efc84fc645f5" or
    hash.md5(0, filesize) == "61647db645f7cc221046999ef1dbe1d1" or
    hash.md5(0, filesize) == "62123c39477389d500e74e82782adea5" or
    hash.md5(0, filesize) == "68e310de44c3165ffffa25bc495d6fc5" or
    hash.md5(0, filesize) == "6cf548445c39aff844be96d73c89e376" or
    hash.md5(0, filesize) == "6d365de5c5a13006b7cadd6bc6876e84" or
    hash.md5(0, filesize) == "6dfef58ef68fb7965a23da8be3141af9" or
    hash.md5(0, filesize) == "717ab7624c192f6f8dd38994116c28dc" or
    hash.md5(0, filesize) == "76c819185e3c8b8557a2c3986ab80a7c" or
    hash.md5(0, filesize) == "78250fa890220821e2b91e31b965de59" or
    hash.md5(0, filesize) == "7d35b4961914ad83a57f8832d8e870d8" or
    hash.md5(0, filesize) == "7da855b2fd9b52f9088e64d656164637" or
    hash.md5(0, filesize) == "80e5bde401d6b0ca96015ae9cfeb6535" or
    hash.md5(0, filesize) == "83f66862c0cc40da20236fd6b47138fd" or
    hash.md5(0, filesize) == "841b7d3863b49f62d4faa9949ff5df38" or
    hash.md5(0, filesize) == "84bb66a982710c5536143a07d84e8749" or
    hash.md5(0, filesize) == "8db0adf8fd6dc6195d7ae55e37e49f97" or
    hash.md5(0, filesize) == "911a21aa999c324dc960d3498eec528e" or
    hash.md5(0, filesize) == "96dbdc2651d829bf9ba35674dd4bfcae" or
    hash.md5(0, filesize) == "9810ea6752112b3569ddc096e1a72e1d" or
    hash.md5(0, filesize) == "9f37fff7e5d22f83fc1c0872ad5332f9" or
    hash.md5(0, filesize) == "a36082c998391a3ebaf05ba4f834172c" or
    hash.md5(0, filesize) == "a3dba01c76571adc0797801ff30f2b90" or
    hash.md5(0, filesize) == "b36968b98046d1b033d84f292e7ca1cb"
}
