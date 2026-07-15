import "hash"
// Salamander CTI  //  https://salacti.com
// Targeted espionage against Cambodian government entities

rule Salamander_Khmer_Shadow
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Khmer Shadow"
    malware = "Unknown malware"
  condition:
    hash.md5(0, filesize) == "03e7a4065df354a99add76e8ba7dd37b" or
    hash.sha1(0, filesize) == "04e7a98fb3b7738cca42557c3e2d9906d04fa2f6" or
    hash.sha256(0, filesize) == "15278c52f4e0d8b5bbfe288a5e826ab2ebeaedb7fb85572940cf1263e384761f" or
    hash.sha256(0, filesize) == "1852120a84a328edd1995e633dfd2009867898a8e3f0b385e2490cf21c77a994" or
    hash.sha256(0, filesize) == "90bbfa9e7af176b85d110f4f1789cae6777fcb60813b047133c8f12caa344a17" or
    hash.sha256(0, filesize) == "b3e853eee14fb7948c6907888ee07139085ba9af4231c30e97ff6236b86ca024"
}
