import "hash"
// Salamander CTI  //  https://salacti.com
// Inside FortiBleed: Reverse Engineering the CyberStrike Harvester Behind a Global FortiGate Credential Factory

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "CyberStrike Harvester, EKZ Infostealer"
  condition:
    hash.md5(0, filesize) == "7f74bb6ba185978134c318bc5f91d23c" or
    hash.sha1(0, filesize) == "268a8420b791df46380ed9ad69905207e15d8a7c" or
    hash.sha256(0, filesize) == "2758f4d71a2a2dfdefab81737c2d776b2a3dafe5844fdd2157e089a28447ca98" or
    hash.sha256(0, filesize) == "38353f95fff270f4e3a9d7add8c64666020dd668ce66e15969a736ec48cadc59" or
    hash.sha256(0, filesize) == "4253dd1a4c0867b0be7732f75b2f630cebfb7fed94270e15fb3b12ae40546d01" or
    hash.sha256(0, filesize) == "479ae5fd7274439ddfa27bc03298ebfdfc5ff17f6412acccf74d4dbd90d94218" or
    hash.sha256(0, filesize) == "874bcb1c3d050a5b5b333a2198f504fcb27927c2abdd43b07440188a380c52d5" or
    hash.sha256(0, filesize) == "9eaa577c8ba71646928c1c34c3145536b0498f65f26060a6ba00744bcef57644"
}
