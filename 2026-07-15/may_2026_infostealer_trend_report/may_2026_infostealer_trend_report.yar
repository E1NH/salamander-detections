import "hash"
// Salamander CTI  //  https://salacti.com
// May 2026 Infostealer Trend Report

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "LummaStealer, Remus"
  condition:
    hash.sha256(0, filesize) == "46e32500cd24395dd140293758e72fe8671217f5f5b0307858fc118a125aab8c" or
    hash.md5(0, filesize) == "0d1f6685b4e284f92ef25c0f9358bcdc" or
    hash.sha1(0, filesize) == "7d5c1d672d6e4bef1a7ca4ca9849db74e8690213" or
    hash.md5(0, filesize) == "03b24f56cafa09024e80b105c667b027" or
    hash.md5(0, filesize) == "055df00e748fe55d5bbc0bd33067325e" or
    hash.md5(0, filesize) == "0a437c4161b4ed8de7850f8de970824d" or
    hash.md5(0, filesize) == "0b8a891324d65f3d9e08dd04980cb66e" or
    hash.sha1(0, filesize) == "91ff54e44ec5684d89c29a95742c083d35b01e47" or
    hash.sha1(0, filesize) == "b7b5b80706f24bc065203080938ec1893170502f" or
    hash.sha256(0, filesize) == "41f81ed33379889b557d7a35d71e347caf6d428df2bf88cf2ed347064fb8de9f" or
    hash.sha256(0, filesize) == "74877ea7d1112b1f7e6949815c81c5083b739adf3d5322dd480abe93c0657656"
}
