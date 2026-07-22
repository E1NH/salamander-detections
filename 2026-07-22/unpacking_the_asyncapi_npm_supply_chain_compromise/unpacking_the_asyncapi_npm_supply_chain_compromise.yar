import "hash"
// Salamander CTI  //  https://salacti.com
// Unpacking the AsyncAPI npm supply chain compromise and import-time payload delivery

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Miasma, BLUERABBIT, GigaWiper"
  condition:
    hash.sha256(0, filesize) == "34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1" or
    hash.sha256(0, filesize) == "082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab" or
    hash.sha256(0, filesize) == "bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4" or
    hash.sha256(0, filesize) == "9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b" or
    hash.sha256(0, filesize) == "d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7" or
    hash.sha256(0, filesize) == "8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c" or
    hash.sha1(0, filesize) == "c70e105e212ff3c1daa04bb2a62507717f296b0b" or
    hash.md5(0, filesize) == "d602f4eeb914cf32782799376a8c5953" or
    hash.sha1(0, filesize) == "93d8cffab1171a115228808e526d9bd7fe935e4e" or
    hash.md5(0, filesize) == "69813c330d52f2a93082651c071a302c" or
    hash.md5(0, filesize) == "71e67d32d2a6e052893dc0c679f9f7fd" or
    hash.md5(0, filesize) == "8c09a52a15a6e617e2b6ccee11046805" or
    hash.md5(0, filesize) == "cd961d0b7b29996b795ddc80c09cc5d9" or
    hash.md5(0, filesize) == "e67c6be63e55148de424e030cf6bed3b" or
    hash.sha1(0, filesize) == "1f5c2e809d1ebd369d34ac22b771c522ced6e5b4" or
    hash.sha1(0, filesize) == "46a236cc9f140deb62bbcfb055e7865d5b23ad81" or
    hash.sha1(0, filesize) == "9b65b9f1bb27cef7b8a2b0327a47a539b8e473fb" or
    hash.sha1(0, filesize) == "ef2d28477befaa103031c7182a6f0dd6b4bb82dd"
}
