import "hash"
// Salamander CTI  //  https://salacti.com
// Don't Fear the Repo: UNK_DeadDrop Phishing Campaign Targets Developers to Steal Cryptocurrency

rule Salamander_UNK_DeadDrop
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "UNK_DeadDrop"
    malware = "Overlord, OtterCookie, Invisible Ferret, FlexibleFerret"
  condition:
    hash.sha256(0, filesize) == "2812e0847d472cb8870c94f463331dbe53b84135132b9bf5f6d84c2382be628f" or
    hash.sha256(0, filesize) == "339907b44f161f57ff30819f422c552382ff437b3ae437463b4222cfe86bd943" or
    hash.sha256(0, filesize) == "35813f4401d3ad77b618275473a556eb47bfa6f4b7439dd8943b19f81aa7252e" or
    hash.sha256(0, filesize) == "4c0d9b802c075be79e9edb52d88f8dd72e6904f5c58267213745818470945c78" or
    hash.sha256(0, filesize) == "4f7a8c3d2e1b5f9071a6b2c8d4e3f50a92b1c7d6e8f4a30b5c2d9e1f7a6b8c4d" or
    hash.sha256(0, filesize) == "52886aab179f26421678ff23af1b0fabf0a17ffbb534369cdbbac8008cbed8e7" or
    hash.sha256(0, filesize) == "62761f38ed194c59abe15c49f09f0ebc431ac852c965180c9327ed84d3a454fb" or
    hash.sha256(0, filesize) == "6cf9f7b2aa456a0b438600588df869b38d8007e28f01fa96022f9d8059f120b0" or
    hash.sha256(0, filesize) == "734699773e53d995f20d485eb61261033d9d00b4332b39ca26071bcd60cd352f" or
    hash.sha256(0, filesize) == "808e7154b7af2bc7a4b28d577297c55f77221c355191cbe00f9f1810b6d4a619" or
    hash.sha256(0, filesize) == "91b9381d19b2e6a2db5cc0307167979b502731cb3fb50da684479e9ed35261aa" or
    hash.sha256(0, filesize) == "a2b9a769df84d9d3a4694bb0252a2c6a5e5f5d1a85a04565362737092bbb3a86" or
    hash.sha256(0, filesize) == "bb10adac5b0124efedfe71102c1d5638135ec9e1cde8c8cb3353c5ed91bb9f81" or
    hash.sha256(0, filesize) == "c935808147f0236c81483d7bbeda4b9d602f3595d5d4057f8115d39e222d1c4b" or
    hash.sha256(0, filesize) == "d3ebce2f05fe91a8260e87fd11a6ea17c156703d081b3f91d9bbe5fd6aeedc10" or
    hash.sha256(0, filesize) == "d5e9288693aa745dc89368deac677e7ea1ec81e663283af30838cdae189b7a7e" or
    hash.sha256(0, filesize) == "e1bf1b29e6fa3525d7f32f429290a88d6ea2890e61c06574b8ff6372aa5d0667"
}
