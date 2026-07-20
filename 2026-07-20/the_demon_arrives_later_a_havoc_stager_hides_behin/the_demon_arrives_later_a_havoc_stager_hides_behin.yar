import "hash"
// Salamander CTI  //  https://salacti.com
// The Demon Arrives Later: A Havoc Stager Hides Behind Microsoft Defender DLP

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Havoc, KongTuke"
  condition:
    hash.sha256(0, filesize) == "fb3630822b70bacb56aa4cec29b5a0e3e9acb3920809e70310a4003385a6d34a" or
    hash.sha256(0, filesize) == "0743154262c5ccf24794168ee331feeefc6539386715307ee44d5d9b6b321077" or
    hash.sha256(0, filesize) == "d24216d0b82747e9406a696da76960183926145f9621947e34a772137f5e22a6" or
    hash.sha256(0, filesize) == "f2357e70f359803d42298d016c7e1631e9fba6c7e01e5df1eb8fb9ff7eb3df4e" or
    hash.sha256(0, filesize) == "3578e1588846a805ee806fa6151b5801d0acb88879a93d378300e2ee7665736e" or
    hash.sha256(0, filesize) == "7d4fb94f6b4623690daea67ed52e97705cb102f443988ff605f2a9c4898244dc" or
    hash.sha256(0, filesize) == "eca5c297008e7c07a5c6fc9070c03121d702ef093b4a8e508b712040d87fed36" or
    hash.sha256(0, filesize) == "1d09357b6a096fdc35cd5c873eed15665d6b3c879d20c8cf01e6bca0005512cf" or
    hash.sha256(0, filesize) == "d2c637235d62ad766f961f9b8563f6a0e6db2ec0a343470385991b4df826afbc" or
    hash.sha256(0, filesize) == "1fc515870c681bf3e1b7947e2248bbcfe9918db2978117e91134de20bd42fd6a" or
    hash.sha256(0, filesize) == "ced6b0f4441085bb9c54a32da9ab4ba14c6e21daf6e34fd61d54923f87baacd0" or
    hash.sha256(0, filesize) == "afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c" or
    hash.sha256(0, filesize) == "2cd88d5280a61714836f5f07a16df190911c5b952af2998dbbcda910b3b1c494" or
    hash.sha256(0, filesize) == "00d979bdb1b29b2859f2120580f101f40e8e13de0b3b7bc29675e2c31098a03c" or
    hash.sha256(0, filesize) == "ae8cded2822c56dd85f52bba09d9285cb2db3e6317227530b848ea143afb067c" or
    hash.sha256(0, filesize) == "9eefc66d1fca7f18a91f49affb569b41bcde043f91567e7f5cc9f2016aeddf8c" or
    hash.sha256(0, filesize) == "c958de72460256c9c1cceef527d880862e8bc29e3ae4e2d478af97dcafd41180" or
    hash.sha256(0, filesize) == "6dc41555455860b8584d761303a7ae5487117944e2a24d74fa3e91ad8f840077" or
    hash.sha256(0, filesize) == "6b22df0de0a40ff372973639c8a1974cfb75084b8e3b85f9ab9038e0acce43c0" or
    hash.sha256(0, filesize) == "31f27fdc14505e0cebe360579e1ba0326762cbe0948e50b5f920da51fdef1b51" or
    hash.sha256(0, filesize) == "389a6a2007e4f06d16beac0ec2cb01391f80ad5e392343386cae3ceb82ec1502" or
    hash.md5(0, filesize) == "01b43dad62e56164771db696827a30ae" or
    hash.md5(0, filesize) == "07d0d4c580ac76ac3ffb63353c9b6b85" or
    hash.md5(0, filesize) == "19b2f2902825eaf62f2db1eb8aaa520a" or
    hash.md5(0, filesize) == "347a3f5f2ed2f503a22f68c4951c78c7" or
    hash.md5(0, filesize) == "37b996509ce2873f96781c9f9b12d8b5" or
    hash.md5(0, filesize) == "37e065585c573ecc082aacbfd31564eb" or
    hash.md5(0, filesize) == "4442897e3b772dfa4f7af109bec8924d" or
    hash.md5(0, filesize) == "609c3fc64a67630a7b206a6880c893a8" or
    hash.md5(0, filesize) == "63e45ffa6d0c22cb04646ef549d61065" or
    hash.md5(0, filesize) == "659575cb45a67b4d0c70e7361709fb03" or
    hash.md5(0, filesize) == "6b8ec32dc76fa3138f00616156962f4f" or
    hash.md5(0, filesize) == "6ee4050ac0c5192961c9f34568ca68fd" or
    hash.md5(0, filesize) == "7d384886720c8e576c3ca9d68cb5f08b" or
    hash.md5(0, filesize) == "9d066964414cff647beeecb75affb5b5" or
    hash.md5(0, filesize) == "a9198c1497481b2fea007ea5f13eafbf" or
    hash.md5(0, filesize) == "ce9abf0dab1facd7afeb70dc34925a78" or
    hash.md5(0, filesize) == "e6c69f14d7b0dabff5c67e54cf87aba2" or
    hash.md5(0, filesize) == "f799ea5df9ec08690385d0972aefb59d" or
    hash.md5(0, filesize) == "fa9d1f3e719d9284af8af075b1cef9cc" or
    hash.sha1(0, filesize) == "149f5cfe98e06f9f7fb6d29dd271830c02250f9d" or
    hash.sha1(0, filesize) == "29b38a57b22f0a442e4e731525aeada927ea2f56" or
    hash.sha1(0, filesize) == "2b258b5cd3fc997d537ab92b7ebe2d42349a6f92" or
    hash.sha1(0, filesize) == "34e20e58b54e241596dfb2b87451b42f6bbaea95" or
    hash.sha1(0, filesize) == "5a7caaed79b1302285c371960ee3f50779f26a81" or
    hash.sha1(0, filesize) == "70bee643d79fd82f7835b208e15a6d722f64dd7a" or
    hash.sha1(0, filesize) == "86ff1313888780942c6a0ad2f683312911582498" or
    hash.sha1(0, filesize) == "aeb63fc27339747fa922f52ae58d32f8c978ee71" or
    hash.sha1(0, filesize) == "af98e97cd49229845123a1063b8c386cc9b2f441" or
    hash.sha1(0, filesize) == "afd1818d136a5cad592fbd81122e2c0a1aaae4b2" or
    hash.sha1(0, filesize) == "b14e1f931f602b1e1985d1362db0e17dd2d2131f" or
    hash.sha1(0, filesize) == "c6c9b69fbfb77f1d07b44991dccc58719c37faf7" or
    hash.sha1(0, filesize) == "d79246b49a00169993de60779cbcec17cae9da21" or
    hash.sha1(0, filesize) == "dafbe5c235051bd6689f4b36a725360c38abdf25" or
    hash.sha1(0, filesize) == "deb10789274bf903060d700b3472fdf094a14763"
}
