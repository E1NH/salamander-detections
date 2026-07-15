import "hash"
// Salamander CTI  //  https://salacti.com
// Operation Poisson – Analyzing a Cybercriminal’s Entire Operation

rule Salamander_Poisson
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Poisson"
    malware = "Havoc"
  condition:
    hash.sha256(0, filesize) == "0378a5ef51b008aa2d6b76bd44a0bf061339bc3b737a188ec82029444d4d18fe" or
    hash.sha256(0, filesize) == "1f00fd604bb18bbe3081f9ce8d741c4029d2a2125eb8888ac4e0d955938059d6" or
    hash.sha256(0, filesize) == "291cb1fd0f2709b4457447cbb87adacf5c36c1bcb0f8754524024d44174bb195" or
    hash.sha256(0, filesize) == "3b7642b0f84e83a36334c608655c6cb7aae774839a6a3488526b853d89830a60" or
    hash.sha256(0, filesize) == "aa7ea19e34567458b4ee66a7cd274181764984bf32123f756a7fdc64d5857b31" or
    hash.sha256(0, filesize) == "c79091ceae7cd592fc08e4854cda7c1182af762b6b126371cc604debdc995fc7" or
    hash.sha256(0, filesize) == "f06e7e1a4363a01ba2a4fee2e28abdd623abf4194bda373f23ff0e151b5c2b45"
}
