import "hash"
// Salamander CTI  //  https://salacti.com
// Inside a TrickBot Variant Using DNS Tunneling for C2

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "TrickBot - S0266, Totbrick, TSPY_TRICKLOAD"
  condition:
    hash.md5(0, filesize) == "8d5b3a0512744efc132afa6fc75c64d8" or
    hash.md5(0, filesize) == "f7f2f482f3bc6345a44e4a6d647731ae" or
    hash.sha1(0, filesize) == "48fd2036b6556c6747197e07f1706bcf58a27518" or
    hash.sha256(0, filesize) == "105f652e6b8f31c371f2385877e43b6772aff5d3168d5d4635f8a1fcbb321421" or
    hash.sha256(0, filesize) == "33c331ededbf8ee9829895424423ce3fd17e359d2e784fcbce396aacff458cf5" or
    hash.sha256(0, filesize) == "3b19a82e1354ac14a3da7c840cbdd0ce50db38432d78e767b36f08e45024c23d" or
    hash.sha256(0, filesize) == "6c677eb2b3ffd288083c59a13d7bb712d4754af61a5563873f76c440962346f4" or
    hash.sha256(0, filesize) == "bf80245ba792992fbfe24abac33f8fd66f24cdeb5f0f21cfdf45a29d107c8d3b" or
    hash.sha256(0, filesize) == "df527a5c2fbde43816cd02f4cd49eee4bb82fb4a3c7045021360888c7d504c98"
}
