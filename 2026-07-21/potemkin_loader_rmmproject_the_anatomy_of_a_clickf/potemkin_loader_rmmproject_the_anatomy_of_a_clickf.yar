import "hash"
// Salamander CTI  //  https://salacti.com
// Potemkin Loader & RMMProject The Anatomy of a ClickFix Attack

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "MetaStealer"
  condition:
    hash.sha256(0, filesize) == "79f7b67ce8b39070f3e1c2b90fce0ce84134782a7dedcccc1edac197ee9e089b" or
    hash.md5(0, filesize) == "d37cc44db90a65341263deb162024447" or
    hash.sha1(0, filesize) == "4537b37b65e9dc35640d750f3fa7f4944534f6b1" or
    hash.sha256(0, filesize) == "2abe5dd3a057fdef935722e50e9251c272d29fd26113187b853a1f9a9cb89d9b" or
    hash.sha256(0, filesize) == "2ada24dd6e517f37942b749c2bd57ddd97445e9853002cee70a0bc30d0b0ce3a" or
    hash.sha256(0, filesize) == "3b7ae925e2d64522b4f69b56285b05aeca8c5aab5ab46a9c02c4fafb69d881ce" or
    hash.sha256(0, filesize) == "cd4e5e2c65b1660470d3446539ee68adf5faeece3eaeb46583623be9911ee145"
}
