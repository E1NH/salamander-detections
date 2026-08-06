import "hash"
// Salamander CTI  //  https://salacti.com
// ChainDrop: The Mini Shai Hulud npm worm's latest wave hits keyv and cacheable

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Unknown malware"
  condition:
    hash.sha1(0, filesize) == "35a672cf34b996b91f3e1c28cbf3a05a37e036e4" or
    hash.sha1(0, filesize) == "f525d52ceb966516686b482d3dc0137028cc6a63" or
    hash.sha256(0, filesize) == "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668" or
    hash.sha256(0, filesize) == "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc" or
    hash.sha256(0, filesize) == "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb" or
    hash.md5(0, filesize) == "4140f7e17e6f97f83aa3472473e01add" or
    hash.md5(0, filesize) == "7bcf8d9f6834c44450eac145a967d2f2" or
    hash.md5(0, filesize) == "f92ee93a0af971a3966bfa8efa9c2625" or
    hash.sha1(0, filesize) == "e65b155ce74f3f81fb7d2b5b60f8e62b36e6d69c"
}
