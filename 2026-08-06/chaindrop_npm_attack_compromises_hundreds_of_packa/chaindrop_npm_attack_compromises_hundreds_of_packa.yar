import "hash"
// Salamander CTI  //  https://salacti.com
// ChainDrop npm Attack Compromises Hundreds of Packages

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Unknown malware"
  condition:
    hash.md5(0, filesize) == "00ca0c04d247ef09f2b2acc452029345" or
    hash.md5(0, filesize) == "dbb9b09957113463bbeb420c2c4108b5" or
    hash.sha1(0, filesize) == "7b0278216ac31ec18eca9eb8bc1c1261a1b26f6c" or
    hash.sha1(0, filesize) == "ff7ed7a0fa1c43eed01809d076feedbaed464fc7" or
    hash.sha256(0, filesize) == "14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128" or
    hash.sha256(0, filesize) == "927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f" or
    hash.sha1(0, filesize) == "35a672cf34b996b91f3e1c28cbf3a05a37e036e4" or
    hash.sha1(0, filesize) == "f525d52ceb966516686b482d3dc0137028cc6a63" or
    hash.sha256(0, filesize) == "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc" or
    hash.sha256(0, filesize) == "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb" or
    hash.md5(0, filesize) == "4140f7e17e6f97f83aa3472473e01add" or
    hash.md5(0, filesize) == "7bcf8d9f6834c44450eac145a967d2f2" or
    hash.sha256(0, filesize) == "3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7"
}
