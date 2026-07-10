import "hash"
// Salamander CTI  //  https://salacti.com
// LBIOC-20260071 - The Gentlemens Leak

rule Salamander_The_Gentlemen
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "The Gentlemen"
    malware = "Gentlemen, Unknown malware"
  condition:
    hash.md5(0, filesize) == "a88daa62751c212b7579a57f1f4ae8f8" or
    hash.sha1(0, filesize) == "c0979ec20b87084317d1bfa50405f7149c3b5c5f" or
    hash.sha256(0, filesize) == "7a311b584497e8133cd85950fec6132904dd5b02388a9feed3f5e057fb891d09" or
    hash.md5(0, filesize) == "408dd6ade80f2ebbc2e5470a1fb506f1" or
    hash.sha1(0, filesize) == "e00293ce0eb534874efd615ae590cf6aa3858ba4" or
    hash.sha256(0, filesize) == "4c82fbafef9bab484a2fbe23e4ec8aac06e8e296d6c9e496f4a589f97fd4ab71" or
    hash.sha256(0, filesize) == "3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235" or
    hash.md5(0, filesize) == "4200b46a93c6ab059e2b34ce200c4a5b" or
    hash.sha1(0, filesize) == "42bcc743c71a9ea083c1c750a398110582796762" or
    hash.md5(0, filesize) == "de1a114a2c5552387a1bbb61501bf129" or
    hash.sha1(0, filesize) == "d6aaed67606d6dab0f652c755d3d363025f60adb" or
    hash.sha256(0, filesize) == "62c2c24937d67fdeb43f2c9690ab10e8bb90713af46945048db9a94a465ffcb8" or
    hash.md5(0, filesize) == "0b33a1a23b044beb5c9a63aafd35595c" or
    hash.sha1(0, filesize) == "00ff099e3cf7b548a7a0260cde8ac2f24a746da2" or
    hash.sha256(0, filesize) == "860a6177b055a2f5aa61470d17ec3c69da24f1cdf0a782237055cba431158923" or
    hash.md5(0, filesize) == "f4ae5b89db5a6a36dbd98287ab7c860a" or
    hash.sha1(0, filesize) == "36d968425629b10f38be17787f8afe4b8afa131e" or
    hash.sha256(0, filesize) == "992c951f4af57ca7cd8396f5ed69c2199fd6fd4ae5e93726da3e198e78bec0a5" or
    hash.md5(0, filesize) == "30b49ae2f685d4403d3013410f80c2e2" or
    hash.md5(0, filesize) == "5f5bf7fc7a9ac89ce0bbb07bd1160078" or
    hash.md5(0, filesize) == "6ae7c9a7ea0b8c40a64225734f6bd01d" or
    hash.sha1(0, filesize) == "5264a94271d875675336a503c94ece0baceb58c5" or
    hash.sha1(0, filesize) == "68225c5613afe2174ed46e074147676b0f9a3915" or
    hash.sha1(0, filesize) == "8468cb5888fb383d25f9144c2b2f61c414cea3f8" or
    hash.sha256(0, filesize) == "025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a" or
    hash.sha256(0, filesize) == "2ed9494e9b7b68415b4eb151c922c82c0191294d0aa443dd2cb5133e6bfe3d5d" or
    hash.sha256(0, filesize) == "48d9b2ce4fcd6854a3164ce395d7140014e0b58b77680623f3e4ca22d3a6e7fd" or
    hash.sha256(0, filesize) == "5dc607c8990841139768884b1b43e1403496d5a458788a1937be139594f01dca" or
    hash.sha256(0, filesize) == "87d25d0e5880b3b5cd30106853cbfc6ef1ad38966b30d9bd5b99df46098e546c" or
    hash.sha256(0, filesize) == "8c87134c1b45e990e9568f0a3899b0076f94be16d3c40fa824ac1e6c6ee892db" or
    hash.sha256(0, filesize) == "91415e0b9fe4e7cbe43ec0558a7adf89423de30d22b00b985c2e4b97e75076b1" or
    hash.sha256(0, filesize) == "994d6d1edb57f945f4284cc0163ec998861c7496d85f6d45c08657c9727186e3" or
    hash.sha256(0, filesize) == "9f61ff4deb8afced8b1ecdc8787a134c63bde632b18293fbfc94a91749e3e454" or
    hash.sha256(0, filesize) == "a7a19cab7aab606f833fa8225bc94ec9570a6666660b02cc41a63fe39ea8b0ad" or
    hash.sha256(0, filesize) == "b67958afc982cafbe1c3f114b444d7f4c91a88a3e7a86f89ab8795ac2110d1e6" or
    hash.sha256(0, filesize) == "c46b5a18ab3fb5fd1c5c8288a41c75bf0170c10b5e829af89370a12c86dd10f8" or
    hash.sha256(0, filesize) == "c7f7b5a6e7d93221344e6368c7ab4abf93e162f7567e1a7bcb8786cb8a183a73" or
    hash.sha256(0, filesize) == "ec368ae0b4369b6ef0da244774995c819c63cffb7fd2132379963b9c1640ccd2" or
    hash.sha256(0, filesize) == "efaf8e7422ffd09c7f03f1a5b4e5c2cc32b05334c18d1ccb9673667f8f43108f" or
    hash.sha256(0, filesize) == "f736be55193c77af346dbe905e25f6a1dee3ec1aedca8989ad2088e4f6576b12" or
    hash.sha256(0, filesize) == "fc75ed2159e0c8274076e46a37671cfb8d677af9f586224da1713df89490a958" or
    hash.sha256(0, filesize) == "fe1033335a045c696c900d435119d210361966e2fb5cd1ba3382608cfa2c8e68" or
    hash.md5(0, filesize) == "05e9d6d239ea29f0427b02a9bc903be7" or
    hash.md5(0, filesize) == "0a454a07e071971832985701bc6e9164" or
    hash.md5(0, filesize) == "0f9cd505df07e4ebfff3fe61b689e527" or
    hash.md5(0, filesize) == "1cc9ae55b1856e4e9796c73f94c2e683" or
    hash.md5(0, filesize) == "1e0f4cd09aa4464179933769b5009251" or
    hash.md5(0, filesize) == "3b46a729db7ae6af8b19711c9452194d" or
    hash.md5(0, filesize) == "4609cbac6772a6c61fcf2745cd3b4362" or
    hash.md5(0, filesize) == "7a89b347beb55f63dbcbcfc0beedbe43" or
    hash.md5(0, filesize) == "7b885b446bbd9b450146c88f84c64f30" or
    hash.md5(0, filesize) == "7f11809925adc6657e84165fdf780816" or
    hash.md5(0, filesize) == "a2a13b8da7370f5f4753d81c7958dfcb" or
    hash.md5(0, filesize) == "ed18c524e930cd1c34614f7cc3051dfc" or
    hash.md5(0, filesize) == "ffb6011e7c82355046988166dd896930" or
    hash.sha1(0, filesize) == "124b943f6e82135b4d680df111ce121a200606dc" or
    hash.sha1(0, filesize) == "143cb70aede3ba09ae54e1da55c69f0129991f48" or
    hash.sha1(0, filesize) == "23a468d7277902384875d4167a81164bc2bf6e72" or
    hash.sha1(0, filesize) == "54a207ed34d83d1f71d34d4ad538e8221ffba259" or
    hash.sha1(0, filesize) == "5aea74bf3e70f38eb596f8002b3c02514daee4f0"
}
