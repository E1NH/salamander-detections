import "hash"
// Salamander CTI  //  https://salacti.com
// LabubaRAT: A Rust Based Remote Access Tool Masquerading as NVIDIA Software

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "LabubaRAT"
  condition:
    hash.md5(0, filesize) == "d8bf355a198fb5db3ea65cfdfcdfbd19" or
    hash.sha256(0, filesize) == "8c4e4804f21649e5ddc6a5670f3b3828a43bff304f02f184f9842c2569570f3d" or
    hash.sha256(0, filesize) == "b7443b0ab48d2f5786d1b6f3a580f02621e9ae5a3877ee3a44e01df13d984328"
}
