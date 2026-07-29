import "hash"
// Salamander CTI  //  https://salacti.com
// Analysis of BlueShell Variants Used by APT Groups

rule Salamander_BlackTech
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "BlackTech"
    malware = "BlueShell"
  condition:
    hash.md5(0, filesize) == "fdc9e765546c72841221b86fe1383c37" or
    hash.sha1(0, filesize) == "d7513a05ff14ee84594ec97c1defa37a1e430770" or
    hash.sha256(0, filesize) == "3228da011423853efd3d94ce3a28046b5ca19e921861ea5aee2700bc90fc1d55" or
    hash.sha256(0, filesize) == "944b774d592f5e7fe2c34ac6c3abb2a77bfa96707c4f3c33ac77b8d54800244f"
}
