import "hash"
// Salamander CTI  //  https://salacti.com
// PamStealer: a Rust-based macOS infostealer that validates credentials through PAM

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "PamStealer"
  condition:
    hash.md5(0, filesize) == "bae0005a0bf0d467a672600833eeed92" or
    hash.sha1(0, filesize) == "e291f991d4bd616203b291a36121dc8b0c15f509" or
    hash.sha256(0, filesize) == "06fdd1d97df1105c542ddb881d751b659d555b5522c266f6364dae9f350fcfd0" or
    hash.sha256(0, filesize) == "2b512f6c393edad89a89ecafe26cd23b71cfdd271c10522f8dba98997ebf39bb" or
    hash.sha256(0, filesize) == "36d46ac7123e0cef04f179d88e590891c7e7c64ec5a77df4512cb485e40286da" or
    hash.sha256(0, filesize) == "60df952153696d46a09774e44ca602393c6829f9e2c2ec4f95d571f9846242a8" or
    hash.sha256(0, filesize) == "96c8ad78f6ccdf83d3dcabfd33ba563f7995f7237fe825de1eefd340821abdf3" or
    hash.sha256(0, filesize) == "ab3a14096851cc18a253c1cd1c25df74f2cf23eb29051784ce47f9fc318f0f22" or
    hash.sha256(0, filesize) == "bb01f3c36110d2cc31ae51c4ff2f17be19bea625755b5339680431fab98616df" or
    hash.sha256(0, filesize) == "ca7f5c0668f1a871523d485e42884c3b98910117d7ca17c8b3c3b3744a936e0f" or
    hash.sha256(0, filesize) == "e8b18c420669deb8fc6f69e74146e499057c3c77436ac6ca54af37befa9ddaa5" or
    hash.sha256(0, filesize) == "f48b69e4b7fb4d53de25b4c9be8e8dbe0999c10d5306e01aa08e1761fc3dedbe" or
    hash.sha256(0, filesize) == "ff20b429cb1c89e1cdb6734b00cc8cf021d2d13fd686bbc70709b3dd549285d2"
}
