import "hash"
// Salamander CTI  //  https://salacti.com
// A rigged game: compromises gaming platform in a supply-chain attack

rule Salamander_APT37
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT37"
    malware = "BirdCall, ROKRAT - S0240"
  condition:
    hash.sha1(0, filesize) == "21ca0287ec5eaee8fb2f5d0542e378267d6ca0a6" or
    hash.sha1(0, filesize) == "2c6cc71b7e7e4b28c2c176b504bc5bdb687c4d41" or
    hash.sha1(0, filesize) == "5b70453ab58824a65ed0b6175c903aa022a87d6a" or
    hash.sha1(0, filesize) == "d9a369e328ea4f1b8304b6e11b50275f798e9d6b" or
    hash.sha1(0, filesize) == "f9f6c0184cee9c1e4e15c2a73e56d7b927ea685b" or
    hash.md5(0, filesize) == "7331602726f61959d8f0e7820d457370" or
    hash.sha1(0, filesize) == "03e3ece9f48cf4104aafc535790ca2fb3c6b26cf" or
    hash.sha256(0, filesize) == "33d887ca2e57fa03fc807dfba5376bf96718ee88f56e90d95ee4896a2c019bd0" or
    hash.md5(0, filesize) == "23a1eacad84be4f2c5830755b1948582" or
    hash.md5(0, filesize) == "3d3d2dc34f01bcf890f185a5421836c7" or
    hash.md5(0, filesize) == "72ac1287a8d71b27c437ec1f379ab506" or
    hash.md5(0, filesize) == "a0830ce48537ba052f1d3b905d11a5bf" or
    hash.md5(0, filesize) == "a48b62e55a692bf6d1046d2be64d7150" or
    hash.sha1(0, filesize) == "01a33066fbc6253304c92760916329abd50c3191" or
    hash.sha1(0, filesize) == "2b81f78ec4c3f8d6cf8f677d141c5d13c35333af" or
    hash.sha1(0, filesize) == "409c5acaed587f62f7e23da47f72c4d9ec3144d9" or
    hash.sha1(0, filesize) == "59a9b9d47ae36411b277544f25ad2cc955d8dd2c" or
    hash.sha1(0, filesize) == "7356d7868c81499fb4e720f7c9530e5763b4c1d0" or
    hash.sha1(0, filesize) == "95bdb94f6767a3cce6d92363bbf5bc84b786bdb0" or
    hash.sha1(0, filesize) == "b06110e0feb7592872e380b7e3b8f77d80dd1108" or
    hash.sha1(0, filesize) == "fc0c691db7e2d2bd3b0b4c1e24d18df72168b7d9" or
    hash.sha256(0, filesize) == "185633e5dbe9235fc7e6a1ccb8631650afefd8f7da88c5c07d9b99ea38159822" or
    hash.sha256(0, filesize) == "415b253a81e67c8c860a97c73edc9017ce732b3c025d943d3b1a445b4ac82822" or
    hash.sha256(0, filesize) == "5aa7afd790481ad98357636fa4d9927ae01111409c8d7ce69998d2485c1d5e6f" or
    hash.sha256(0, filesize) == "95cda8431419f77407484ab72dc1e356421dcd801eccabe8869f77ee0eb58eb2" or
    hash.sha256(0, filesize) == "dfa9c6adac98311d0f62e0eeecb947d92f7bda41ddf4ce9a6f9e20af7990422d" or
    hash.md5(0, filesize) == "a8fe823d451d636d0a0366c0629ef5c3"
}
