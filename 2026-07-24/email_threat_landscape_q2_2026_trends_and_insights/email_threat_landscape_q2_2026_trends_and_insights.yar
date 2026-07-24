import "hash"
// Salamander CTI  //  https://salacti.com
// Email threat landscape: Q2 2026 trends and insights

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "11420d6d693bf8b19195e6b98fedd03b9bcbc770b6988bc64cb788bfabe1a49d" or
    hash.sha256(0, filesize) == "5db1ecbbb2c90c51d81bda138d4300b90ea5eb2885cce1bd921d692214aecbc6" or
    hash.sha256(0, filesize) == "b5a3346082ac566b4494e6175f1cd9873b64abe6c902db49bd4e8088876c9ead" or
    hash.md5(0, filesize) == "467f4c566f8a49fa9bc5d36f50f89568" or
    hash.md5(0, filesize) == "99ce8ecb93b9a43c5697bfa9cbd13b7b" or
    hash.sha1(0, filesize) == "7d509d135292020a317b0f7a2f444b665396e891" or
    hash.sha1(0, filesize) == "f5d0ee4f6eb348d10ccaa4f24cae392782b9bfa3"
}
