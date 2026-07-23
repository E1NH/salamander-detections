import "hash"
// Salamander CTI  //  https://salacti.com
// JadeProx: Tracing a China-nexus Operation Through an OPSEC Mistake

rule Salamander_JadeProx
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "JadeProx"
    malware = "Fscan, PlugX"
  condition:
    hash.md5(0, filesize) == "b8053bcd04ce9d7d19c7f36830a9f26b" or
    hash.sha1(0, filesize) == "3ba9a74f8faeff3de03e4c834f266582e2eb46a8" or
    hash.sha256(0, filesize) == "e82ecbe3823046a27d8c39cc0a4acb498f415549946c9ff0e241838b34ed5a21" or
    hash.sha256(0, filesize) == "35feef0e6806c14f4ccdb4fceff8a5757956c50fb5ec9644dedae665304f9f96" or
    hash.sha256(0, filesize) == "d5590802bf0926ac30d8e31c0911439c35aead82bf17771cfd1f9a785a7bf143" or
    hash.md5(0, filesize) == "88ac1c5fc9ee89491c70ea16131e264a" or
    hash.sha1(0, filesize) == "910465739b3170584150e9260bfba6a65e633f35" or
    hash.md5(0, filesize) == "c64eda499e2a21ad158841b9dbc7adc9" or
    hash.sha1(0, filesize) == "3de213252d98348a7d833c4956a099bfcd36b9e2" or
    hash.md5(0, filesize) == "0482d6053f96e6bde0a92af25497f3c0" or
    hash.md5(0, filesize) == "0e6d22c2a81d29b1f9d8395d44e19e53" or
    hash.md5(0, filesize) == "35cdbf8a16da1245d574a0365cb87287" or
    hash.md5(0, filesize) == "38e317af0fc0efcc88265f243a264542" or
    hash.md5(0, filesize) == "39d4012e49f58092ec5cefed13dbbcfd" or
    hash.md5(0, filesize) == "3b3dd8f3a5e1ff85c63f2453ad270415" or
    hash.md5(0, filesize) == "3fe9c84025f4401f8cd661675642c526" or
    hash.md5(0, filesize) == "4faf4fd91d28e014b4f2362d6a7bb8ac" or
    hash.md5(0, filesize) == "5222a31cf24f9f57ae3d1831f264a983" or
    hash.md5(0, filesize) == "5b75b00a4b4c32b6e213514e80500a65" or
    hash.md5(0, filesize) == "7840f30b395fac347f85b38633c2d08d" or
    hash.md5(0, filesize) == "796f82a4833be330b1e35af63e55b597" or
    hash.md5(0, filesize) == "7c84e75817349adcdea9925b86f67670" or
    hash.md5(0, filesize) == "8002ab4d0cf7e1888ee72de0b9f4282c" or
    hash.md5(0, filesize) == "853f760f76de3201b0af0e41f1f65fba" or
    hash.md5(0, filesize) == "9e01bf0e28c86435cfb1afaef44238e9" or
    hash.md5(0, filesize) == "a4cdecc57a215243d279cdb065863308" or
    hash.md5(0, filesize) == "aedd185b76ccda8d65dbd26204cc0e9a" or
    hash.md5(0, filesize) == "bb5c88de9e04e6306260b9f3a4498933" or
    hash.md5(0, filesize) == "bef0b8599d18acf1c74192ae9f198f85" or
    hash.md5(0, filesize) == "c1f45a0609c5c1bd2c21cad20703f126" or
    hash.md5(0, filesize) == "c512adfa8743c3b3c776d4452f00c6c0" or
    hash.md5(0, filesize) == "d99392248bdd7e351e63ead6733638ba" or
    hash.md5(0, filesize) == "df1f03a2534480a4838f62339bcb90d8" or
    hash.md5(0, filesize) == "e067ffea77875ae0dc13d4ce045931d3" or
    hash.md5(0, filesize) == "ee5a2cdd4ce6ccb2e9279c9e13e8bd15" or
    hash.md5(0, filesize) == "efac43473d7e87ede5176fe01a114abb" or
    hash.md5(0, filesize) == "f2ce6fe8b52dfbacfee482a48f4ae972" or
    hash.md5(0, filesize) == "f360afe51b499a036c7be8c0ecc4dc89" or
    hash.md5(0, filesize) == "fef1d3cb35129ad25d95e279565b9001" or
    hash.sha1(0, filesize) == "3915dfb85d698abe2d5b4285bef1fb0f63520ea3" or
    hash.sha1(0, filesize) == "4a7545fa95cf3ede0ef796f04bed7d0c9afe5276" or
    hash.sha1(0, filesize) == "97918307c96d4357c81caf7ca6f942c32f43857e" or
    hash.sha256(0, filesize) == "8f2e8a2f9d3edc12d39ca07f4717277e863d4bfeb8ec31fe4f391ddd0f64df84" or
    hash.sha256(0, filesize) == "d38e05a6fea310e778a8b1e623ee9b00f430ee76622f7a66cd0ca538fcaa1613" or
    hash.sha256(0, filesize) == "d4d249c621b5c27fd96505d041674ea472d5dec0a7730b44324c8af6a7fb7f0a"
}
