import "hash"
// Salamander CTI  //  https://salacti.com
// One Misconfigured Server, Three Active Campaigns: Full exposure of three AiTM Phishing Operators

rule Salamander_codemado
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "codemado"
    malware = "AsyncRAT, MaDoO Blaster, Evilginx"
  condition:
    hash.md5(0, filesize) == "1a37b674ed29c877890834e9aba616d9" or
    hash.sha1(0, filesize) == "ea5d2096a2ef3dfe4fb870bd1f0270efaea993a6" or
    hash.sha256(0, filesize) == "7f30259d72eb7432b2454c07be83365ecfa835188185b35b30d11654aadf86a0" or
    hash.sha1(0, filesize) == "2ea61cdead470f570586f513e22d43d787befec6" or
    hash.sha1(0, filesize) == "35f23dfb4135d4cd38a6a29e64d79191d166344d" or
    hash.sha1(0, filesize) == "6a4cb1c75e1c59bbd4fbc4667f4c3bb5a74fe965" or
    hash.sha1(0, filesize) == "cf3cbf93adf43d50618c88705857d3adb123ed24" or
    hash.sha1(0, filesize) == "e9a44b3fe951cca57313533d6bc1d11e789c2018" or
    hash.sha1(0, filesize) == "eb8ede7598220dbef28953dc7df2e5418d52fa36" or
    hash.sha1(0, filesize) == "f496736e2d2344de7963d4f722381f03227ec452"
}
