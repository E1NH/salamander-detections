import "hash"
// Salamander CTI  //  https://salacti.com
// What Is the BabaDeda Loader? Analysis of a New ClickFix Malware Campaign.

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Arechclient2"
  condition:
    hash.md5(0, filesize) == "b2e581c85432bd4df6a59a00cbda1cb3" or
    hash.md5(0, filesize) == "2efaac26a7e8c4efaaf643f19cb8b978" or
    hash.md5(0, filesize) == "3c32116f5e98f5920c2d9f2b19755077" or
    hash.sha1(0, filesize) == "bf43af6116053819ebd41ee1deb40f85446c774d" or
    hash.sha1(0, filesize) == "c11d639851e27293cddac5eec891e909cc641821" or
    hash.sha256(0, filesize) == "0c0dc13805564d986b5eac6c5e8c90d336256fbb7f8a0c52180f1f5c690fe203" or
    hash.sha256(0, filesize) == "1e1d25391cf825d9607f652249e33cf1d2b98f260b587a1b1b33710e2ea6b91f" or
    hash.sha256(0, filesize) == "2afa7b6f825ae82c0121117b2966c57d825e7f1cfecaef36e638f66a08060db6" or
    hash.sha256(0, filesize) == "3b4208ec304b60ba9d0ca74838ad7031224a32c36d6e1fa7c616a5ecf5074a5b" or
    hash.sha256(0, filesize) == "3e881c9663db5c80a0093f4b0f7008aa1e73866c57aa672e53b38274df4c2807" or
    hash.sha256(0, filesize) == "425501b6428e19536be925b4a286f73ae94270bc23ac516832ea27ba6c875998" or
    hash.sha256(0, filesize) == "5c6144b1bb4c195a4dcd7ebac8c427852c7e15cb5b4f5217dda0cfb39a90062a" or
    hash.sha256(0, filesize) == "71f19394bf15ae47b668fcbe13d0fe4d46d8c06ce004eeccf82c8d1770bba558" or
    hash.sha256(0, filesize) == "7eb345c26a1b827e7b2ef5b7881cb406b04b056ebc36cc92e3f7643decd2671f" or
    hash.sha256(0, filesize) == "809d030d1fd65c909260b4b33bff9c99f775aea332d944ad1f64b4e5e81a6d60" or
    hash.sha256(0, filesize) == "91255813151e6fb3d2a45e088490214c110ff035bbd1ee01ff430782868c77b3" or
    hash.sha256(0, filesize) == "9677584602ae15bdd20d91b9a14768a17c126107739e3853d969ff4e02e10e71" or
    hash.sha256(0, filesize) == "9a736f4812b485f9cf5b1332a791b205b5135a4b3a0c41f473ad9cc9fbe2d75c" or
    hash.sha256(0, filesize) == "a8a2148d6cf70d06a9c2ecded8b1a21f982cf11ffc9774442209f536a66a8630" or
    hash.sha256(0, filesize) == "c92950568a2b757d4ee0bad84b33f5b3414f0d5fdf3d3f5b06e7d304a7ccf1a1" or
    hash.sha256(0, filesize) == "d79a454beabcd59459c350c71598bffd6badb6a8905b0e9fa3c1ee22cbef7d7e" or
    hash.sha256(0, filesize) == "dcd612f1d86ff5c9b43f1a3d0baea16b9c08e4b844bcd82564c720ee1caafe3c" or
    hash.sha256(0, filesize) == "e38550a29e4ff48d8cd4df5ab34a88b9b28f23d50e66129c896689cd334849a9" or
    hash.sha256(0, filesize) == "fa25acfac32c557f809ab544764d4348f31cf9909ad9d512883d6cba8369ba88"
}
