import "hash"
// Salamander CTI  //  https://salacti.com
// Compromised npm Packages in the AsyncAPI Namespace Deliver Miasma Botnet Loader

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Miasma"
  condition:
    hash.sha256(0, filesize) == "34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1" or
    hash.sha256(0, filesize) == "082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab" or
    hash.sha256(0, filesize) == "bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4" or
    hash.sha256(0, filesize) == "9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b" or
    hash.sha256(0, filesize) == "d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7" or
    hash.sha256(0, filesize) == "6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71" or
    hash.sha256(0, filesize) == "b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292" or
    hash.sha256(0, filesize) == "b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a" or
    hash.sha256(0, filesize) == "8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c" or
    hash.sha256(0, filesize) == "550af477c12192a22f5c9edb9c8081c0a789b3a1a2992a7ecb157cca1c975e10" or
    hash.sha256(0, filesize) == "24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168" or
    hash.sha256(0, filesize) == "9e214f38537e69bf51c7fa1ddd35ae495e9cb897231ec010baf9e4f29407ee9a" or
    hash.sha256(0, filesize) == "9f1a709310824f9110c6203d861a721ebefba8b204a8657057fe57efb961c850" or
    hash.sha1(0, filesize) == "3eab3ec9304aa26081358330491d3cfeb55cc245"
}
