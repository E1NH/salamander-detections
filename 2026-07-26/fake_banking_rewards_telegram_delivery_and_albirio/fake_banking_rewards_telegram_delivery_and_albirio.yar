import "hash"
// Salamander CTI  //  https://salacti.com
// Fake Banking Rewards, Telegram Delivery and Albiriox: Anatomy of an Android Malware Campaign

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Albiriox"
  condition:
    hash.md5(0, filesize) == "6aa665d2f33f03a549c14edec772cf2c" or
    hash.sha256(0, filesize) == "146c62f408b6d7db4c832a6b5f7bdacb1cff2c69121b9b2f7e80646c37910abd" or
    hash.sha256(0, filesize) == "1e99972b1d84b131eb55a6b49f64871c5c0c6a1bb2a099a84313001b69dc53e8" or
    hash.sha256(0, filesize) == "206fdbe992b44ebd6720c49c79a5da3bdcb48d0d799a0ff3458323caac3cc490" or
    hash.sha256(0, filesize) == "4b9a95ebf5e471d11443fa2f19b75595fc1fcf6be234024cc1d4a2255068c19b" or
    hash.sha256(0, filesize) == "e0fc365c042e708c8d04b5431238958586194cc4a8cbe069411a26dcfcc4e9b6" or
    hash.sha256(0, filesize) == "efc81267da3ad48cc779e9aed8f9232504ed7c85abf3958a87ba2ae68056ae23" or
    hash.sha256(0, filesize) == "fb43c4191c40f159167a98a4ac20bf23ae66a8ec27a919f703e953933e22a266"
}
