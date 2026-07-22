import "hash"
// Salamander CTI  //  https://salacti.com
// HelloNet campaign: a threat via the ViPNet update system

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "HelloInjector, HelloProxy, HelloExecutor, HelloCleaner, HelloBackdoor"
  condition:
    hash.md5(0, filesize) == "0cfdffc56f0fa325d0c4d24780b46597" or
    hash.md5(0, filesize) == "16c211c96735f2fae9361b89bd7a31bf" or
    hash.md5(0, filesize) == "1bfe2b9493128574907a8279256a8bcc" or
    hash.md5(0, filesize) == "41c938b3cd7e55d4077e34976929b140" or
    hash.md5(0, filesize) == "6001829a128fe264b4403138700c11a8" or
    hash.md5(0, filesize) == "9f5606a0755bc633b9bd7db6d179c09e" or
    hash.md5(0, filesize) == "b103cd21280b4061f88b2bcc51394894" or
    hash.md5(0, filesize) == "ee4ff46ddd8489e81447962f927bc3f6" or
    hash.md5(0, filesize) == "f9eed2f0158dc98e7012fb809152209c" or
    hash.sha1(0, filesize) == "686292c07e33c4a5ca456db446bb71fb9fc67a81" or
    hash.sha256(0, filesize) == "ffdc194775b2904564bbbd1cf0eb01d1a01f83ef5197d1612b6e2d69de7a4732"
}
