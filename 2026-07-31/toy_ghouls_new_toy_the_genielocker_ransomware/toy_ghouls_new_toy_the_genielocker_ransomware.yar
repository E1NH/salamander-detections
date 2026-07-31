import "hash"
// Salamander CTI  //  https://salacti.com
// Toy Ghouls’ new toy: the GenieLocker ransomware

rule Salamander_Toy_Ghouls
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Toy Ghouls"
    malware = "GenieLocker, RedAlert, LockBit, Babuk - S0638, Babyk, Vasa Locker, Mimikatz"
  condition:
    hash.md5(0, filesize) == "18f61c6d686cffd131c9fd3f3437064b" or
    hash.md5(0, filesize) == "25480dad40152ef3d0c6d38eecc9bd9b" or
    hash.md5(0, filesize) == "34a7f28e0bb69b0d49bacc88bdf20ac1" or
    hash.md5(0, filesize) == "34b8828635f88078735799a3c1ac8e28" or
    hash.md5(0, filesize) == "3a4479b51890373bfc4a011ef41fe376" or
    hash.md5(0, filesize) == "58c0dda52b8f069660166d61fd74f911" or
    hash.md5(0, filesize) == "5d62c1349b8981c396c9a23f4f8f053c" or
    hash.md5(0, filesize) == "780c8f4c6f077da4da96582987920362" or
    hash.md5(0, filesize) == "7dad78584795aa5c160520cc6accf260" or
    hash.md5(0, filesize) == "824ca1e906cc073ee5b0f3519df69a8f" or
    hash.md5(0, filesize) == "9201e35e2993612612919a3c71302cab" or
    hash.md5(0, filesize) == "9969a8221312dba70dd5cbddf83a146c" or
    hash.md5(0, filesize) == "9cd514ff2809ce0b993e3b8649e82a94" or
    hash.md5(0, filesize) == "a50eaaf514f4f84e61ca2455a8789753" or
    hash.md5(0, filesize) == "a8842616c9057d5cf6e1fe1fa8c3c160" or
    hash.md5(0, filesize) == "b893eafed0659f70d4ac250f09073723" or
    hash.md5(0, filesize) == "c68b6862725777651085650db34947fc" or
    hash.md5(0, filesize) == "d3e06eb34d8eee7ef92cac3ad0a20ff5" or
    hash.md5(0, filesize) == "d661cf666b9acbab7cfeae1127a261a9" or
    hash.md5(0, filesize) == "d87d0b01d95acc936b7dc47b8f41937a" or
    hash.md5(0, filesize) == "de3cfbb50f66079bfee20a6f64e59433" or
    hash.md5(0, filesize) == "f08f476f26b01d142ca73923de65fc0c" or
    hash.md5(0, filesize) == "f7b9e36e94163a9a303160945f99267a" or
    hash.md5(0, filesize) == "fd46a80c2f45577263328984edf7f4dc"
}
