import "hash"
// Salamander CTI  //  https://salacti.com
// QuickFox Supply Chain Attack Used to Deploy FDMTP Implant

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "FDMTP"
  condition:
    hash.md5(0, filesize) == "03fd832b81dd54d2bf5f610a8ff27856" or
    hash.md5(0, filesize) == "19e760ee849eb7c1f100f2b7010a763d" or
    hash.md5(0, filesize) == "1f3031167f94b166cc7b69376a01c124" or
    hash.md5(0, filesize) == "2dd8681dcd218c88d1c78dfe939ec92b" or
    hash.md5(0, filesize) == "2ffdcfb7157511789228988e26d06fd6" or
    hash.md5(0, filesize) == "30d59c3d4916aa5fb24050c6aae7f8e4" or
    hash.md5(0, filesize) == "3b79d95f7f7b58c401a3bc79f94ebb52" or
    hash.md5(0, filesize) == "5e4ed6abbf555e5a542e3d4308ccd7bf" or
    hash.md5(0, filesize) == "5f3daf7417dd666213168eb6c7453cc7" or
    hash.md5(0, filesize) == "b1d344c9a1525373be6a3980fa85a603" or
    hash.md5(0, filesize) == "e0a92209dd62dae8460d934dc6b7ddd7" or
    hash.sha1(0, filesize) == "11a6df1e15663ae89f59a9e598ae8987f42a632b" or
    hash.sha1(0, filesize) == "173dd4190740b96f6f733c801b6428ed4b52b607" or
    hash.sha1(0, filesize) == "2cc0425a90a39ac4eedadd59caaafad5b50f8420" or
    hash.sha1(0, filesize) == "3449a349b6c8045b16df4f88d58c65c2bdf891bb" or
    hash.sha1(0, filesize) == "39504cead410056878962053f8d027e9f299cd10" or
    hash.sha1(0, filesize) == "7ab7ffe4c233a4f2440f0fdeb2e117c788792281" or
    hash.sha1(0, filesize) == "a195810c41f401c4b48cb557cf8ce60c2d807025" or
    hash.sha1(0, filesize) == "b194a997c9a653134bdb1f2d0c3137dcdacb54d5" or
    hash.sha1(0, filesize) == "b370b674ce877b9c0a7708c7834aeb7eda983564" or
    hash.sha1(0, filesize) == "c41b4e11e6a9e3b53da1f92b213de9f65a825c92" or
    hash.sha1(0, filesize) == "e90d2730f3354ff1adf334b03c95eac3207d47b9" or
    hash.sha256(0, filesize) == "2b6cdafdfe427a3de1a94a8a2ca1f09fc4c8f90e4f59089fd9b35b73185ed01c" or
    hash.sha256(0, filesize) == "3bd3b300f3278520819a06d0cb1f0eadbf946dbbc11352538246ff075eb427f1" or
    hash.sha256(0, filesize) == "5cbb64375636e83b5f17d6083633cecc02e2a5f4168cd7cca5cdee36ccca9b38" or
    hash.sha256(0, filesize) == "6634339b813e6105b5138de6ab67b016b8dfbf49233c29de9bab3207e8b50d24" or
    hash.sha256(0, filesize) == "6932a20ac61fd3f93d7cfee414f6f46834068ac7c9ca011b054a6a10dc56b3d1" or
    hash.sha256(0, filesize) == "7462ce2595119c928cf516ec33148dc2a39dd9f71636a5c849c7ed93b7c5ca06" or
    hash.sha256(0, filesize) == "795594ad5e6f2868cc4d8ed12dabf4f3999a1477c6b250527c5ede9a98528fb9" or
    hash.sha256(0, filesize) == "a53d756f28457b1c4a239c91cdec8ed7b7da67a93e332e6df9621cbef8417474" or
    hash.sha256(0, filesize) == "a5d36edc34fe54b2092349f877daf560a98f5fea635d1ac4a110b3518102ef96" or
    hash.sha256(0, filesize) == "d9db5cbc193ddaf4c0a265804fdef70c32451daaf2974fa9adf52ce1defac5f7" or
    hash.sha256(0, filesize) == "dc666e9c148bbca5e21d8c9a97143575c075f53360f135e0191aed9e8278d396"
}
