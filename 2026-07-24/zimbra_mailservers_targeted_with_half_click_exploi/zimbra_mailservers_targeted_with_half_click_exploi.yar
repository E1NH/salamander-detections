import "hash"
// Salamander CTI  //  https://salacti.com
// Zimbra Mailservers Targeted with Half-Click Exploits

rule Salamander_TA488
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TA488"
    malware = "ZimReaper"
  condition:
    hash.md5(0, filesize) == "c010f64080b0b0997b362a8e6b9c618e" or
    hash.sha1(0, filesize) == "e3ce7d13a83716594787a12edf6cbeedc76b9a65" or
    hash.sha256(0, filesize) == "98df604ecc57f884a2e6ce3266a0013ad64455cac48442c2312cfa4765007aaf" or
    hash.sha256(0, filesize) == "1517b3caa495f6c4e832df9c75fc94667e3c233773f7fa4e056d5e30e5ead760" or
    hash.sha256(0, filesize) == "60db9abae75cd8ccc49dd7ea5feb41677566dcd442f12ebc5745ffd2810fb874" or
    hash.sha256(0, filesize) == "b1f5beb1175fc5c7d1806a2f0d900eb124c54f0286c5c52b66eea7a6633adb1d"
}
