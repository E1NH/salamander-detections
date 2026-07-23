import "hash"
// Salamander CTI  //  https://salacti.com
// PHISH ALERT: From a Simple Phishing Email to a Full Attack Arsenal: The Evolution of "ClickFix"

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "7b7981c99d59595fe15377df84695bb72ce0b85560a3935f930657b2d162e5ef" or
    hash.sha256(0, filesize) == "adcd15f3d6b87f84d106ea426fa824fd20c9d64f6d199ce92580884290785f30" or
    hash.sha256(0, filesize) == "d7d2f0ee187549f3f4a114d716be12521fbf62d6d26e2ac23d2a32d521d08fd8" or
    hash.md5(0, filesize) == "79e205576bdad2cce593ae850b0c9e31" or
    hash.md5(0, filesize) == "e5989c374fa9cb1bc53b202032257a3c" or
    hash.sha1(0, filesize) == "5442dea013b109ac4d0cdc52248b758a6cb9684c" or
    hash.sha1(0, filesize) == "e46d05b8aa8f1b1a5e81da2ebe2bf8e94cbe85fe" or
    hash.md5(0, filesize) == "7596699747d2b284df77d2c83714aa00" or
    hash.sha1(0, filesize) == "5cf01e24f6bafa64815d1bd2f3323ea091d504cc"
}
