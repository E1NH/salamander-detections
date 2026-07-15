import "hash"
// Salamander CTI  //  https://salacti.com
// From Fake Amazon Security Alert to HarborWatch Agent: ClickFix Delivery of a Custom Monitoring RAT

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Unknown malware"
  condition:
    hash.md5(0, filesize) == "09c121225fe254676a27c21943506714" or
    hash.md5(0, filesize) == "33760b2aa86deea5805e647197c34ef5" or
    hash.md5(0, filesize) == "9abebe5a34eefb80db12bf8d51bfe7f7" or
    hash.sha1(0, filesize) == "b31f62e1d3b28808daad3ec5efa5df54ae56898d" or
    hash.sha256(0, filesize) == "3a87cab1e8c6868a7939eb422f1851ecc746405cda6b3d3502b9d8eedc360898" or
    hash.sha256(0, filesize) == "5f7bb80bf85c1fae7413eb534cc2f022402c8753f75666525adb1dc85a677f4c" or
    hash.sha256(0, filesize) == "cf94ff2ecc4f3157704c9cfed5e446c405e7729141019045cb05ef6ffad122d5"
}
