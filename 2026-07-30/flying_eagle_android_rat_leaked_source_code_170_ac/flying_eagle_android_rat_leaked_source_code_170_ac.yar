import "hash"
// Salamander CTI  //  https://salacti.com
// Flying Eagle Android RAT: Leaked Source Code, 170 Active Servers, and a New Platform Called Night Dragon

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Flying Eagle, Night Dragon, SpyNote, BTMOB"
  condition:
    hash.md5(0, filesize) == "18827998ad05c58da1d218066374fe16" or
    hash.md5(0, filesize) == "645ee92d197441684919c0b1ad5cfd15" or
    hash.md5(0, filesize) == "81694f8296ea8e589acc68382add4311" or
    hash.md5(0, filesize) == "b5f64311ffe3c6f1eb13b769663702c6" or
    hash.md5(0, filesize) == "d23e2d0c71cbf0a5d67e17e7b3c690e0" or
    hash.sha1(0, filesize) == "5d95ddf7cd857acaaa3447e710a3ee596262b4e2" or
    hash.sha1(0, filesize) == "68389a8ae359c2e730e33ab60e9fa6ad71120983" or
    hash.sha1(0, filesize) == "d767524b3b288f09840f3d7196718e4187515f6b" or
    hash.sha1(0, filesize) == "e02955f78fca6c758d760c36474ae0d4f546efb4" or
    hash.sha1(0, filesize) == "e9c71b51de94d6ef1f1090a36754d987374f6f70" or
    hash.sha256(0, filesize) == "0376db397807c1f1e32a99a9db622f35f4fe5597bd05b4fd5e93117062e0131f" or
    hash.sha256(0, filesize) == "1456f31bf6b5d4ade90fe080006478133296080353bf69c1819fa9b766e7f57a" or
    hash.sha256(0, filesize) == "4395db6ad53a415532673b16f5b64207d53cecc5b15a736c038cf3890368a164" or
    hash.sha256(0, filesize) == "5dee5cde6f2874c582effe302960b21569ee007e9e0cd4f7499d418cceb9095b" or
    hash.sha256(0, filesize) == "773c77494d6321e4e449c9558c7915166bcb6c05e3c42a9d30e5eac4db8ee0df" or
    hash.sha256(0, filesize) == "7fe8d14e7a9cda92c79d5ae836ed95d772bcc853079c4020c5213c3894c7f7af" or
    hash.sha256(0, filesize) == "82520e6aa6194b2de0b1c404805a5da7d3693acab8f7ae2dd5104f14baf82cd7" or
    hash.sha256(0, filesize) == "b803cd5032dc1abd7aabc45c8cadc471c8a59872a95d48807f13e230c58230f3" or
    hash.sha256(0, filesize) == "c692ad120cc90548d48dbe57d006f2403c49833b8993af3c38fe031eb39999bd" or
    hash.sha256(0, filesize) == "d8a82d7b4457352774772bfac094127d7f67526ae7011d838cc3f7ccc15fd86e"
}
