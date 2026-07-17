import "hash"
// Salamander CTI  //  https://salacti.com
// June 2026 Infostealer Trend Report

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "XWorm"
  condition:
    hash.sha256(0, filesize) == "d15248555e7a2d9c279d219e6587a74fca9c25720194512a2e4b0757f7a63219" or
    hash.md5(0, filesize) == "02c7d78e6c5816f1df250f995a776aa2" or
    hash.md5(0, filesize) == "03663f2f81da94cd204837e4bde772ff" or
    hash.md5(0, filesize) == "03e99ceede013fe1b50a0e06c1f0a02c" or
    hash.md5(0, filesize) == "042db31ea5443d78aeee714556813a28" or
    hash.md5(0, filesize) == "04d91c168c7617c38199983858cfbb4e" or
    hash.sha1(0, filesize) == "c8c80cde1ae90d6a594980e117977437de97ebb1" or
    hash.sha1(0, filesize) == "dbe028a59ffe936bce9acb56e9c2db93ef6f84fe" or
    hash.sha256(0, filesize) == "ac14d191300c2d3aa9f57829b895b7720be1ef3563bace25de731002d52577f7"
}
