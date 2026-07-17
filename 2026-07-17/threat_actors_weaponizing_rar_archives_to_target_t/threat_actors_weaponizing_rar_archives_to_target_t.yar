import "hash"
// Salamander CTI  //  https://salacti.com
// Threat Actors Weaponizing RAR Archives to Target Thailand's Healthcare Sector

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Braodo"
  condition:
    hash.md5(0, filesize) == "8a5dadc5faf424df1e8a0efad023df81" or
    hash.sha1(0, filesize) == "4a1a6ed11fd50b621659d7976899d050ba2e15d3" or
    hash.sha256(0, filesize) == "442e0f4e822842922e7e4685840194e99fd68c7f0ec38c1925914b8f724d5865" or
    hash.sha256(0, filesize) == "4eebc38297a307d18784d6f9ebc8aa6e6f69860be970cc70d9e544deb1ff6ce0" or
    hash.sha256(0, filesize) == "523388567630e4fbdc359f75232bf2ad82671a680d4bfdce0237fc30dfec4c80" or
    hash.sha256(0, filesize) == "74bb6ad7e1310f30a3e24fd3cbbffa2c0c41c64e89e5d0dd1d6900e96b914183" or
    hash.sha256(0, filesize) == "7709d8c34d490509f3624104611eb75a862944dd9d7a642f44514ada16c85ee9" or
    hash.sha256(0, filesize) == "e5f6d9d405819e6b05b5d8268a2e973294859ad65237ede36ab612b536d0ac2b" or
    hash.sha256(0, filesize) == "f4d4b8cac004bb63834c6df436721babd9464c09787c80b268d839e0aada9f87"
}
