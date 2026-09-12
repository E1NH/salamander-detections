import "hash"
// Salamander CTI  //  https://salacti.com
// Gray Rabbits and the Tale of a One-Click Backdoor

rule Salamander_UNC3569
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "UNC3569"
    malware = "GRAYRABBIT, RABBITFUR"
  condition:
    hash.sha256(0, filesize) == "29c7ee41d0cc9e07d981e451df56d0c3d37c41ac4ec10c7b516cc033ee397a63" or
    hash.sha256(0, filesize) == "749160a2f20f82744026719cf72e483595c6aad718efa74d675a98662e02422e" or
    hash.sha256(0, filesize) == "d7a3c7eb94edc0e020f74c678743d71d61e944634aade4a67a96c3589e828b3a"
}
