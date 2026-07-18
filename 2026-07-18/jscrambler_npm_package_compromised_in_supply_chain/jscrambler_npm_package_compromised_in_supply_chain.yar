import "hash"
// Salamander CTI  //  https://salacti.com
// jscrambler npm Package Compromised in Supply Chain Attack

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86" or
    hash.sha256(0, filesize) == "a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60" or
    hash.sha256(0, filesize) == "b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903" or
    hash.sha256(0, filesize) == "bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0" or
    hash.sha256(0, filesize) == "c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd" or
    hash.sha256(0, filesize) == "fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd"
}
