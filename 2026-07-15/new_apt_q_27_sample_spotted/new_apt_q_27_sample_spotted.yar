import "hash"
// Salamander CTI  //  https://salacti.com
// New APT-Q-27 sample spotted

rule Salamander_APT_Q_27
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT-Q-27"
    malware = ""
  condition:
    hash.md5(0, filesize) == "8838df7298abf4d4312648e2ee80bdee" or
    hash.md5(0, filesize) == "c0aca5dfbbfcb1c9796b3d974b1ee78b" or
    hash.md5(0, filesize) == "1d1808686dbf36138f3067c34566d627" or
    hash.md5(0, filesize) == "130fbe74fea31b30b59b071ccf22bf68"
}
