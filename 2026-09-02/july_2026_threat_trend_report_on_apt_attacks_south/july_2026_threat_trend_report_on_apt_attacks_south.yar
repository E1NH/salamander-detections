import "hash"
// Salamander CTI  //  https://salacti.com
// July 2026 Threat Trend Report on APT Attacks (South Korea)

rule Salamander_Kimsuky
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Kimsuky"
    malware = "XenoRAT"
  condition:
    hash.md5(0, filesize) == "0080cd81db3244b8ba157ffabc1d30fe" or
    hash.md5(0, filesize) == "00f7955410783941d527afc12908556a" or
    hash.md5(0, filesize) == "029628bd99899c750d5537ee637fe3ca" or
    hash.md5(0, filesize) == "03a830875abc607aa30a621eb84697c8" or
    hash.md5(0, filesize) == "09bd2f48fcd29a0ed46b099c4d939024"
}
