import "hash"
// Salamander CTI  //  https://salacti.com
// Phishing on the Edge of the Web and Mobile Using QR Codes

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "NagaPocker.apk, app-u7cp-release.apk, ludashi_home.apk, k12sns.apk"
  condition:
    false  // no file hashes in this brief
}
