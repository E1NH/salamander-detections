import "hash"
// Salamander CTI  //  https://salacti.com
// ClickFix Deno Abuse to CastleRAT

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "f1ecb89facb7e31ee9c03278f4106113c0339ff9fc10b1aefe33aaab776e8540" or
    hash.sha256(0, filesize) == "f704a49c0cdaaae4515105bf937e26b5e39b1101c8a0cefaca3959fce7418e9d" or
    hash.sha256(0, filesize) == "82056127b671583deb500d931ecb893224c34d3b8de66c0959700d55a1bfbbfd" or
    hash.sha256(0, filesize) == "c9afa1e8ce84b3af50304b504519a587488658142137cf4bbf85f5780c06f682" or
    hash.sha256(0, filesize) == "b04bc0780b2cd11fde488372387f557a87fd473ba546295f5fca7771d5b8a394"
}
