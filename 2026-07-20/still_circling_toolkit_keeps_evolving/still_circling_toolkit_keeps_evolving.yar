import "hash"
// Salamander CTI  //  https://salacti.com
// Still Circling: Toolkit Keeps Evolving

rule Salamander_APT_C_36
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT-C-36"
    malware = "AsyncRAT, njRAT - S0385, Njw0rm, LV, Bladabindi, LimeRAT"
  condition:
    hash.sha256(0, filesize) == "a4fbd707f4ce7ca68e6137cef1c56b6f408e5f0a0f148434d996bb98c3a21fff" or
    hash.sha256(0, filesize) == "a73cb9d5d46e19f3daa4a14cfe5d8fa4319a3d62452039e4972e6a316bbb26f4"
}
