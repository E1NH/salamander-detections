import "hash"
// Salamander CTI  //  https://salacti.com
// Kimsuky Uses the AI Agent 'opencode' to Create Decoys as Its GitHub PAT-Based LNK Attacks Evolve

rule Salamander_Kimsuky
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Kimsuky"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "f1bd5817678f498966f033f61b617dee5c8e81191901fea7c4a89146bfe91091" or
    hash.md5(0, filesize) == "10780939962b54addc9d31f57d80edfc" or
    hash.md5(0, filesize) == "1523a2fcc901965ab4568d9fe829e4af" or
    hash.md5(0, filesize) == "500e0bc0d7579fb338912770964076fe" or
    hash.md5(0, filesize) == "685bfc6b2c29fbc16cfad908894add55" or
    hash.md5(0, filesize) == "7a53089053b1381742856a5cf2b95f8b" or
    hash.md5(0, filesize) == "8db2f20b719dcb7029d6296505622093" or
    hash.md5(0, filesize) == "900e832c10d851bbdef3fb191a15db0e" or
    hash.md5(0, filesize) == "a2015665a3e18bf0ef86e3931245c7e6" or
    hash.md5(0, filesize) == "bb88940e915b11f6330b7446f6037f5b" or
    hash.md5(0, filesize) == "ce5932b88f879f26006df81f2fa7667e" or
    hash.md5(0, filesize) == "d0894d4626aae0f96d6b84ca3bb71a36" or
    hash.md5(0, filesize) == "e50f2ae7fb03675a1ef58b1cf9cda6d1" or
    hash.md5(0, filesize) == "f648bdd3c2cd902e239149de86d43e8f" or
    hash.sha1(0, filesize) == "441b709b1a57353a7b127d9a35b5002eee7e6efb" or
    hash.sha1(0, filesize) == "f72bd8bde005b8646d64f6a516407b6f9d2c680a" or
    hash.sha256(0, filesize) == "8d0aad27440fb29f9ab5f1af0f7977ed332d945d4bbeb7af0a96e07ac24eaaff"
}
