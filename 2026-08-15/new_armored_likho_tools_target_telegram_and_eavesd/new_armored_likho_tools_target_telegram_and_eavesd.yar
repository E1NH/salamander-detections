import "hash"
// Salamander CTI  //  https://salacti.com
// New Armored Likho tools target Telegram and eavesdropping

rule Salamander_Armored_Likho
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Armored Likho"
    malware = "Still Sync, Still Audio, AquilaRAT"
  condition:
    hash.md5(0, filesize) == "c1d1ee16b92e6a138ffa048855f75d7d" or
    hash.md5(0, filesize) == "17674b250d8b422a50a86c9ff207186d" or
    hash.md5(0, filesize) == "62801f6223e860a7cca271522e303b2d" or
    hash.md5(0, filesize) == "68f0365d2fa8c828d012d8859e52a773" or
    hash.md5(0, filesize) == "4bd7c352ae277b0e38d07beedd4dd507" or
    hash.md5(0, filesize) == "d4bc09fb10ea2a5dc0bcbeeda5e5afdd" or
    hash.md5(0, filesize) == "2ca8adbab98ebe305eacf272cf48f5a0" or
    hash.md5(0, filesize) == "3ac41b097236a7723821848ae31ef141" or
    hash.md5(0, filesize) == "439255736797bc88bd19f282449e0436" or
    hash.sha1(0, filesize) == "17b6f4984930165939680a09d91989ad82bc57e2" or
    hash.sha1(0, filesize) == "724f6ca2ea66dbf117c7eea42c99760716ec75b9" or
    hash.sha1(0, filesize) == "b9258c816724cb074258df485dfbc5b08141cdcb" or
    hash.sha1(0, filesize) == "dd1f41f6f8e995fb482070d6689f4238505aac78" or
    hash.sha256(0, filesize) == "31349d61da780d59a8a27e2762405632726d88135a08ac5dda05849c62dfd551" or
    hash.sha256(0, filesize) == "404eb4ada6e161210611f1c8275f126ec24aad37c380ead130cf15667023d249" or
    hash.sha256(0, filesize) == "4eb6126f7e23d9155df280b944a98da10a79f1067f39990cf019f25feef75712" or
    hash.sha256(0, filesize) == "5fc1251e474eae9253362a08095e989edc2b63de21d76052a2c849efc6792c3f"
}
