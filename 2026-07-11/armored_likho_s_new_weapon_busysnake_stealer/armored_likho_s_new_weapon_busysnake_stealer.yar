import "hash"
// Salamander CTI  //  https://salacti.com
// Armored Likho's new weapon: BusySnake Stealer

rule Salamander_Armored_Likho
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Armored Likho"
    malware = "BusySnake Stealer, AquilaRAT, Go2Tunnel"
  condition:
    hash.sha256(0, filesize) == "8a100cbdf79231e70cee2364ebd9a4433fda6b4de4929d705f26f7b68d6aeb79" or
    hash.md5(0, filesize) == "393b498f2114cabc0b29d5fcd9dc6723" or
    hash.sha1(0, filesize) == "a0b80c0ec77f62b0ed46edb3fef05ccb88c74afb" or
    hash.md5(0, filesize) == "0041fd1b2358cd08dbcbc28ea8fc3d20" or
    hash.md5(0, filesize) == "006887732ca4a4a46a97989cf4deeef6" or
    hash.md5(0, filesize) == "07213c419489c02791e8d67b91e404ef" or
    hash.md5(0, filesize) == "1096268fa2b3d454c86cf851cb782319" or
    hash.md5(0, filesize) == "1dba3e505491a260a44c867902c3296e" or
    hash.md5(0, filesize) == "2dfa1d949872c1b2f04952dd3e5f5d8f" or
    hash.md5(0, filesize) == "5d5c3e483c5e544260ce98fc29fbf192" or
    hash.md5(0, filesize) == "6b45ddb39a6e86229348dcbba3857e7c" or
    hash.md5(0, filesize) == "7141917cba2eee2b4d31107faccf3a39" or
    hash.md5(0, filesize) == "732c31acf971a81c7e51b2a3dae82020" or
    hash.md5(0, filesize) == "78135f72ab148a0cc074f6b2dd51fff6" or
    hash.md5(0, filesize) == "7db9c688c620e54e8c69b7e52a7579fb" or
    hash.md5(0, filesize) == "80b7700053e115d65365ce7330383320" or
    hash.md5(0, filesize) == "8188b2f347b77d65d08cfb23808ac244" or
    hash.md5(0, filesize) == "894332174f536c2e1efeda05cba79f8b" or
    hash.md5(0, filesize) == "90378881856abfa47d7745c0a3ef9dc8" or
    hash.md5(0, filesize) == "a0ec7a8e61eff3f445a7455b3aef9fbb" or
    hash.md5(0, filesize) == "c019797a00fd56edb1f468ac0a598510" or
    hash.md5(0, filesize) == "c7622a1effa27bbfee6d6e03d6474343" or
    hash.md5(0, filesize) == "cf74ac018d158ea2c2cfa1b1d71d95bc" or
    hash.md5(0, filesize) == "ddff82a115558584bbd7741d4ffb35b4" or
    hash.md5(0, filesize) == "e2550cfad9dcc880bf04f6048f90868c" or
    hash.md5(0, filesize) == "f2ab09d7e7a375a192508a5014aa2ee4" or
    hash.md5(0, filesize) == "f5c6434ee5f7578faa3bc1257e1c9226" or
    hash.md5(0, filesize) == "fd2bdd8047addee6fde2f532de181bfd" or
    hash.sha1(0, filesize) == "2654dfefff26ad290037230bf2dc7353411d0cc8" or
    hash.sha1(0, filesize) == "8436fba39929e8da81fc78b2bc7eb74da6b9578a" or
    hash.sha256(0, filesize) == "00ccbf72b8a0f0314d829766775889bbe9c964ce7b499ff26ba12fb62cadf906" or
    hash.sha256(0, filesize) == "3ec02d6bed160a97edea549ec88c46f10105f6cdf6a4b3f356b2fc6a4a14f386"
}
