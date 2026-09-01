import "hash"
// Salamander CTI  //  https://salacti.com
// ValleyRAT is spreading disguised as adware

rule Salamander_Void_Arachne
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Void Arachne"
    malware = "ValleyRAT"
  condition:
    hash.md5(0, filesize) == "c24e99f9437feacaa63766a3cde3fe3d" or
    hash.md5(0, filesize) == "07ddbbe2c71c45577a7a4fbcdba0df91" or
    hash.md5(0, filesize) == "8a626d844943da3456b044f38deae3a2"
}
