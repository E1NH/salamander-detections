import "hash"
// Salamander CTI  //  https://salacti.com
// RustDuck: An In-Depth Analysis of a Two-Stage Botnet

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Gafgyt, Mirai"
  condition:
    hash.sha256(0, filesize) == "b519ae088ee0fd4658c16aab474d51c6acdc5c9cd7fab3fd69032d05a45ffd9b" or
    hash.sha1(0, filesize) == "4d11bd496da82d15b3ed13050f414e44f5a892d4" or
    hash.sha1(0, filesize) == "6aa791c76b3107fca9d57b7ecea8f46d97d83738" or
    hash.sha1(0, filesize) == "8315f650e9e4f67c00277b076ab304eed23db47d" or
    hash.sha1(0, filesize) == "d39a3ee96be6b8f5238cb1253514ab55c88f714c" or
    hash.md5(0, filesize) == "36e51d11e70c04c60a9c3a4f088ed507" or
    hash.md5(0, filesize) == "9d864a76a4f6dc1d26febd34856c0509" or
    hash.sha256(0, filesize) == "a5d1b65b1055677156cd87b357ef488704115a2cbf52044dbb041072efed2f9d"
}
