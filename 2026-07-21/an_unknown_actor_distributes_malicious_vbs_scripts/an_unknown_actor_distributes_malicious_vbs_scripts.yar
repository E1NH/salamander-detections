import "hash"
// Salamander CTI  //  https://salacti.com
// An unknown actor distributes malicious VBS scripts via WhatsApp

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Ghost RAT"
  condition:
    hash.md5(0, filesize) == "02bb20455cc592a69c080abac770ce90" or
    hash.md5(0, filesize) == "31037a42ca048e06e69a78f55bc2eff5" or
    hash.sha1(0, filesize) == "887ec87e4a19759cad25d4bc0956d2b965d3041d" or
    hash.sha1(0, filesize) == "f0fde01b1e36503227252f6cb6b3b075f93a2c1a" or
    hash.sha256(0, filesize) == "452259dc297f56cf22c7932e8fbcefe821ef9c3127134074fae585f89355d397" or
    hash.sha256(0, filesize) == "50c74b468c217776b8890b841baefec8b196b14083a7873a9201c838a8e4c90a" or
    hash.md5(0, filesize) == "05d188f071d097f5b6bd8138749b4b14" or
    hash.md5(0, filesize) == "0ba93109757776a44de9d8c88baa4963" or
    hash.md5(0, filesize) == "1a3cc75466ffb1971482f7abf7aabc3f" or
    hash.md5(0, filesize) == "1c47c63e5ed25060d95359c57c77b107" or
    hash.md5(0, filesize) == "1d94fbe9cab21278cc3f104bea334d08" or
    hash.md5(0, filesize) == "20209b3a32769afc6a75694b8d8839dd" or
    hash.md5(0, filesize) == "2c6f05f1f309d89b2236e6c8b59c88f9" or
    hash.md5(0, filesize) == "3b1aba44dd3d9b6339b6f56e2f42034b" or
    hash.md5(0, filesize) == "4044e4b6471c9de7b0a4ba37d9d9df9a" or
    hash.md5(0, filesize) == "4f0593e8e0e8fac49429e9b45ebf7fa1" or
    hash.md5(0, filesize) == "5002eca748205d544618e3bd2dedc223" or
    hash.md5(0, filesize) == "5b6bbcc06cf08cc99e1afeda486d42fb" or
    hash.md5(0, filesize) == "6359e6236471cbe434d0ef4c42b7f879" or
    hash.md5(0, filesize) == "63ac85195b73753333316a889cf5880f" or
    hash.md5(0, filesize) == "66442f2457eca8f47385b1fb2c6fcab8" or
    hash.md5(0, filesize) == "66705384a7ad81d14c34fc6c054a0ecf" or
    hash.md5(0, filesize) == "68c16c46f8afb9e00bbaba0207fb0a46" or
    hash.md5(0, filesize) == "6c39900d77dcba158e1d27c7619cb06d" or
    hash.md5(0, filesize) == "6fb6a55424adfb61e31f06aef33273e5" or
    hash.md5(0, filesize) == "7403cbcc5a9c32384d431856dc48fcc9" or
    hash.md5(0, filesize) == "74fd9f91fc93b6288b4fc253ea5b3e20" or
    hash.md5(0, filesize) == "7849061c536a3efb05a56d504694e7e7" or
    hash.md5(0, filesize) == "79ecd61b09b0f2d54b34586c916c4ec9" or
    hash.md5(0, filesize) == "7f16449cd0c4862d1eadf8a5742bf09a" or
    hash.md5(0, filesize) == "7f81c1bc8cfd588e8998968e2621456e" or
    hash.md5(0, filesize) == "8c3322009b8982663c0cbecd9492e7eb" or
    hash.md5(0, filesize) == "8c6d9fc389ad3f20ccbc71d77eb39bfa" or
    hash.md5(0, filesize) == "993f4c0cadbc769a4b0ed62a918db58d" or
    hash.md5(0, filesize) == "9d9ac85765e4a818a3ccabe2cf4fef82" or
    hash.md5(0, filesize) == "9f13c7b8ba391b2f597874e54d310648" or
    hash.md5(0, filesize) == "b7cd06c71465038b658a6dc1f273a507" or
    hash.md5(0, filesize) == "c7f38cbb99c8b74fa0465293feeba700" or
    hash.md5(0, filesize) == "d01cad98dd0d01b75e04e784953c5e2b" or
    hash.md5(0, filesize) == "d06333c360b51456f427e616c3c5f8bd" or
    hash.md5(0, filesize) == "d43fdaa1f0ee09d7e5f0f94ee9df7b6c" or
    hash.md5(0, filesize) == "dad708e050632a4280cabf98ac1376b7" or
    hash.md5(0, filesize) == "ddaffe9849f7f3c79f8804adb9a6b3d5" or
    hash.md5(0, filesize) == "df4fa0369eaca5cec348be293890d4af" or
    hash.md5(0, filesize) == "f90ed4b2d0b67114aa89ddfed658e5c0" or
    hash.sha1(0, filesize) == "8be8f6955de47d980c257ab5bc732cfbd0e23d99" or
    hash.sha256(0, filesize) == "01f1eb07125db5de0c2362afc777aa015f136feabd769628f01d01ac6472646c"
}
