import "hash"
// Salamander CTI  //  https://salacti.com
// StrikeShark: a new campaign involving a custom SharkLoader and Cobalt Strike Beacon

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Cobalt Strike"
  condition:
    hash.md5(0, filesize) == "1f65544978b8ea0e745e573b8ee9684b" or
    hash.md5(0, filesize) == "24fcebdeecba65004fdb0923763d74fd" or
    hash.md5(0, filesize) == "9c872a0d5d5a38950e8b9ac9b488be3f" or
    hash.md5(0, filesize) == "9cbd560f820c95d7c38342cd558cb5c6" or
    hash.md5(0, filesize) == "a514d1bb62d7916475946fe7c07ac0aa" or
    hash.md5(0, filesize) == "aa3086be652c8b20b0b29b2730d57119" or
    hash.md5(0, filesize) == "b3352b42432dedc4a519f011dc8b5d5a" or
    hash.md5(0, filesize) == "c559cc68986933200fd5d9e4388e2f58" or
    hash.md5(0, filesize) == "d98f568496512e4f98670c61c97cb07a" or
    hash.sha1(0, filesize) == "23fd50b3bcc06f5adcbd0122c32260786ec3b98a" or
    hash.sha256(0, filesize) == "6a5f9bd0e4a0c385b98cc7b528be53a95ff9c4ccffa8c1f65448ab792a46186c"
}
