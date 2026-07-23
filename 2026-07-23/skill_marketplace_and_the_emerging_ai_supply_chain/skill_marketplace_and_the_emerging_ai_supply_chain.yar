import "hash"
// Salamander CTI  //  https://salacti.com
// Skill Marketplace and the Emerging AI Supply Chain Threat

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "AMOS, ClawHavoc, cluw"
  condition:
    hash.sha256(0, filesize) == "818aea6143282b352fdfdc0f3ebf77a36e54eb3befb5cad1a355a99ab97c6aa7" or
    hash.sha256(0, filesize) == "881ce5cb124c4d2e814783724cc1388f6a1cbf6eee274c3f3366e77ba3503ad7" or
    hash.sha256(0, filesize) == "b30eaed1f7478c28f4ec50d07ed5ef014ffbc4b2bc5a38d689ba9f7abb5e19c2" or
    hash.sha256(0, filesize) == "b6c7e0bf573b1c7d9d3a05eb08d26579199515b847df984862805f44a7af8007" or
    hash.sha256(0, filesize) == "ebb73dbb5aac1f6fe1a88e8f26126a1e1aa34c9f3345ad4345189b40d9bf1d1d" or
    hash.sha256(0, filesize) == "f4e41aa269c88bf11a2022701a9cf41e9a186aa1b224d837c31bf34e0b875d0e"
}
