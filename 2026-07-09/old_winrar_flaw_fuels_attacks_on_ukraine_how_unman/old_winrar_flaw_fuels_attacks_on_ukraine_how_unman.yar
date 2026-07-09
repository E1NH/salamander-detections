import "hash"
// Salamander CTI  //  https://salacti.com
// Old WinRAR Flaw Fuels Attacks on Ukraine: How Unmanaged Software Keeps the Door Open

rule Salamander_SHADOW_EARTH_066__Earth_Dahu
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "SHADOW-EARTH-066, Earth Dahu"
    malware = "GIFTEDCROOK, GammaSteel"
  condition:
    hash.sha256(0, filesize) == "2a8ea9f1ad8936fb302243faa64b91c5767df411923715cbdb1a869e3bfd7e6d" or
    hash.md5(0, filesize) == "c0b73ff43312d442260328a8cefdf3b6" or
    hash.sha1(0, filesize) == "4528d5cf07bf0e1ac769b390236cab1bf34b938c" or
    hash.sha256(0, filesize) == "7200a9f1e1ea51b66ab9c9274e9d8f805633179634e8ff4dcb8ef82bc02518df" or
    hash.md5(0, filesize) == "2af0a6135df3502a7f6de4d2de6db73b" or
    hash.sha1(0, filesize) == "b1c4a94df23638d70dae45f3193a64a6b036056d" or
    hash.sha256(0, filesize) == "3d371ef71e40c34a75c168d4647db096c2f386499d99a88d4e16b63cd4acda25" or
    hash.md5(0, filesize) == "a84375d4bd67c46d50fef7f7af31c7fb" or
    hash.sha1(0, filesize) == "526833a16669a85f0546809bfc35122e6f0bc17b" or
    hash.sha256(0, filesize) == "1c170b7470d507378ddb78e9d66305f1184e965baaf2d27ededb23a318a58953" or
    hash.sha256(0, filesize) == "2d9adb7932b7842dfb0e0f453b87e5d28dd4552094105e6340bad009956d8c2b" or
    hash.sha256(0, filesize) == "378809699c7252dc38b31969b9cc40858397759f15d6e418246dfaba9088fdd1" or
    hash.sha256(0, filesize) == "37b42a83715f7a34e00d3458d4f4b6e53b8c95372677ce020a2e38e80e60ba87" or
    hash.sha256(0, filesize) == "3c0330f9f934f86b6b70e108ff279a009b88a4a815acbed4adb3664e322e3e59" or
    hash.sha256(0, filesize) == "44f6f7ba668fc645129d66353e6f60402822ae929ce54648cae0bba6348a18ea" or
    hash.sha256(0, filesize) == "4e21c4c97aeb391473ee1e44961676f32de2ee8b56ecb136c1d8081df97c3db4" or
    hash.sha256(0, filesize) == "507b2fcdae058cebbd550965b90c44e878d7a2463058c846eeb68f0dc1b48eda" or
    hash.sha256(0, filesize) == "6083aac5376b7ca74cc363e0d66f70beaffee543d098c612b820b16fbfb0aa52" or
    hash.sha256(0, filesize) == "65c053030558b4a3588e2590c5c4961a9912180b731686deb3f4c831e765a095" or
    hash.sha256(0, filesize) == "718465f44c0680740fb61790eda3d2f4c5218c9de0c560299c580fa1602dc9c7" or
    hash.sha256(0, filesize) == "77963398e2c5c2fdf9d28d9c5f9c2791cfbf422ba02225e01635dd7f5b31eff8" or
    hash.sha256(0, filesize) == "7d3ba419751e5ea52b567e1162f6a366bf3d06c44c8956a9f14520e9fb6ed0b1" or
    hash.sha256(0, filesize) == "8150b2b39fa62fa2de177ed8526c621a3581c0eb481dd9740fc5894ce2b7c13b" or
    hash.sha256(0, filesize) == "82fda6ea769d61aba230c3487787087cec53dd378e22f22a8fb8f0bd5ae83ded" or
    hash.sha256(0, filesize) == "89d20418450b34efe698bd36214100cfa49f60adf1c39a8bc8d65991b1ce2c23" or
    hash.sha256(0, filesize) == "a717dd74c01fcfce35a28f374e1c6f9ded06d6f7b0cc04618ce9454ad64febb8" or
    hash.sha256(0, filesize) == "b01f31c9541579ad34f4e50acafec252eb419f5b1ca98155e0ec84c19d12c9e4" or
    hash.sha256(0, filesize) == "bf338d88f60c0d352cd0d1b5e4bc6a1d9f1ac8fe1df48516ec0042cafda821e9" or
    hash.sha256(0, filesize) == "ce78748acd8e9be741b143ad716d735dc682bd5a010427a199744b81456f8e35" or
    hash.sha256(0, filesize) == "d1d26b0f68e26ac591848796aeef7b9c766442bbff47af8823f9b23d1b588836" or
    hash.sha256(0, filesize) == "dc5082b07eb994ddee343a4080dce0a9ec2e891e5690654e24ae74ba9eabe422" or
    hash.sha256(0, filesize) == "e08dcb80346ded2bb2393a180e3f2612ed4c2ff0d3842390a5b527d003060212" or
    hash.sha256(0, filesize) == "e6bd725a2af981cd2b5c2217c1d7d906369d8daf48f02023fb73635f9e2b9659" or
    hash.sha256(0, filesize) == "e9d6938c9980cab735e8fb2eaa082ddc6f5dd7f2ff84d8ece01e8caaefdbb930" or
    hash.sha256(0, filesize) == "f668bd551859007cf2cc2a62bf0bf5414870a04e9782590c9bf85c849ddb308b" or
    hash.sha256(0, filesize) == "f9d2907d6b1de3078a0f111cc98764a92baf5ebd06cc8ab02637a65eff3b7f3a" or
    hash.md5(0, filesize) == "6a48fbe91482b2f14ed977c110a3685c" or
    hash.sha1(0, filesize) == "f8817d46652594d745f28cb985b0000cf2669352" or
    hash.sha256(0, filesize) == "023c8f8e2a71da2044e3f04ac74c8b3616f417436476cea85222f01119615979" or
    hash.sha256(0, filesize) == "22b07d2af98bb180474c33d93861124bbdf9b5dd7e42a8bddc654310469a9a2c" or
    hash.sha256(0, filesize) == "276789b3b946753e9be482219bc4526da2da8772701f3b9d00c74038e2604ece" or
    hash.sha256(0, filesize) == "2a6ce2445c096fc5e577a0af513ba6f4fb8a8097764c7df81824a782e07e7f65" or
    hash.sha256(0, filesize) == "5d164b6d74dae9fe3022bc3cf453cd8b846e9cdc0cd616246fe620be88e3f1e5" or
    hash.sha256(0, filesize) == "68bafc624a4c0d11ef7a949c0077c704aa5ba0a3205fe5b62d29b727b46ccfe4" or
    hash.sha256(0, filesize) == "c2527a907b209bc4ce911e36b79781ec260f0851eeb466dbeb386d67fec11467"
}
