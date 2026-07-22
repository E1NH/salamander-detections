import "hash"
// Salamander CTI  //  https://salacti.com
// OkoBot framework infection chain

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "TookPS, TeviRAT, Rilide, SeedHunter, OkoSpyware, HDUtil"
  condition:
    hash.md5(0, filesize) == "b07d451ee65a1580f20a784c8f0e7a46" or
    hash.md5(0, filesize) == "187a1f68ae786e53d3831166dc84e6d2" or
    hash.md5(0, filesize) == "d84e8dc509308523e0209d3cd3544619" or
    hash.md5(0, filesize) == "83e6b8fcb92a0b13e109301f8ff649cf" or
    hash.md5(0, filesize) == "7306885bb4c98f2a9f056104cf092bc9" or
    hash.md5(0, filesize) == "b4c2e16cdb513be4dc798f88e2527334" or
    hash.md5(0, filesize) == "2157d2429124ad28db7a26f2477cb985" or
    hash.md5(0, filesize) == "77cecf5e2a622ae07d8ae9913457ab57" or
    hash.md5(0, filesize) == "e0c3bc27a65750e740c4f1719e531c7d" or
    hash.md5(0, filesize) == "3d2b43f91f65bfbf36a9c71b6b418876" or
    hash.md5(0, filesize) == "70fef9fd6e351f4d53cfeee8dcdfcd99" or
    hash.md5(0, filesize) == "acd31c9941b6c1cabd4e45e6877b9038" or
    hash.md5(0, filesize) == "dd52f5108a176c62ad807c327734ad12" or
    hash.md5(0, filesize) == "ac93a821617aea1f56d4bc0bef4af327" or
    hash.md5(0, filesize) == "11dbc8a2bea04b15f8f68f3f01e8faf9"
}
