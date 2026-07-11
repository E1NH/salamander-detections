import "hash"
// Salamander CTI  //  https://salacti.com
// India's government and energy sectors targeted with ZOHOMURK and MINIRECON

rule Salamander_MUSTANG_PANDA
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "MUSTANG PANDA"
    malware = "MustangPanda, Zebrocy, Zedhou"
  condition:
    hash.md5(0, filesize) == "c04c947efdfdd9ce24617903b6746a83" or
    hash.sha1(0, filesize) == "43d646eda4166261eb1433c7599bf5cc9129a4f1" or
    hash.sha256(0, filesize) == "fcf4efa82d477c924d42cc6b71aa672ab2381ca256769925ae34dabe2e77e025" or
    hash.sha256(0, filesize) == "390148f5157c0f6b337ff19d162c3c2ee3e6d782fdfbe11fb1e411c0684fd33b" or
    hash.sha256(0, filesize) == "f53fd0626404a129dcddb8ee7589387dd7bda7999814e0df46c670af6b3da5f5" or
    hash.sha1(0, filesize) == "8aeba3c711eaa0116807c66390284dfa572d2cc7" or
    hash.md5(0, filesize) == "b267acd1b7c15b18178ae9fd4974f3f4" or
    hash.md5(0, filesize) == "7e7b30071565773d480578537ee3b0e6" or
    hash.sha1(0, filesize) == "bca1e295acaacbb19c7e3a7868746f6b772b7b71" or
    hash.sha256(0, filesize) == "5f22ec5c14dfd47c92850a5fb3bd8e3754d538b8021b6238238e4020336cfb5c" or
    hash.sha256(0, filesize) == "a43084f5af861f44c75c5273c779cb26d506cab6b51c33746626da504148a4ec" or
    hash.sha256(0, filesize) == "cd9397797216fd4c08df324937509124e57258328c8e4c6d795c6a2cd25b69b0" or
    hash.sha256(0, filesize) == "ebd533de7ca16daa70093b0b1084fb6136b6ba091d6ee0e4199762581e1b2e5a" or
    hash.sha256(0, filesize) == "f2bed071676feb831ed460489643fd57f6c6c1e0d024a1ea447820276fb13828"
}
