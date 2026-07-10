import "hash"
// Salamander CTI  //  https://salacti.com
// The Package That Never Shipped: Following a USPS Smishing Kit Through DNS Data

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "4fe8bec780537aa223406965415c1f85e83eec1f4e2181cf82e2a7b7516026e6" or
    hash.sha256(0, filesize) == "8e5546c83d764e1287b55cbe868a45344a6f0afa9782d798d03b2b7cfc53ec38"
}
