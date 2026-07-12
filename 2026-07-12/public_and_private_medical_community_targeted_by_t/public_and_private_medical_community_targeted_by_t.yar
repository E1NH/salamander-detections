import "hash"
// Salamander CTI  //  https://salacti.com
// Public and Private Medical Community Targeted by Threat Actor Pursuing Artificial Intelligence, Cyber, Medical, and National Defense Research

rule Salamander_UNC6508
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "UNC6508"
    malware = "INFINITERED"
  condition:
    hash.sha256(0, filesize) == "4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b" or
    hash.sha256(0, filesize) == "51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045" or
    hash.sha256(0, filesize) == "58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86" or
    hash.sha256(0, filesize) == "8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec" or
    hash.sha256(0, filesize) == "ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7" or
    hash.sha256(0, filesize) == "c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b" or
    hash.sha256(0, filesize) == "db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136"
}
