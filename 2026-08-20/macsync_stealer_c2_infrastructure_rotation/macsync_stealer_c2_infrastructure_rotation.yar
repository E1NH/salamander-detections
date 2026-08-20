import "hash"
// Salamander CTI  //  https://salacti.com
// MacSync Stealer: C2 Infrastructure Rotation

rule Salamander_mentalpositive
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "mentalpositive"
    malware = "MacInstaller, Unknown Stealer, Unknown malware"
  condition:
    hash.md5(0, filesize) == "5190ef1733183a0dc63fb623357f56d6" or
    hash.md5(0, filesize) == "277acd8e241c1341852ebcd401203ecc" or
    hash.sha1(0, filesize) == "7d28507870e94b809f25883dc9dae838549ddfac" or
    hash.sha256(0, filesize) == "2728a7d444cd65550f652a8c66eaced0fe6d0389161f86393ab73da8f446a362" or
    hash.sha256(0, filesize) == "7980485fb1e0b1b1d6307a92b5750c7055bc53b662005cbaa662ac634984363d"
}
