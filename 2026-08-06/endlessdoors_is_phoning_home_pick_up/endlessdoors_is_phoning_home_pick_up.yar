import "hash"
// Salamander CTI  //  https://salacti.com
// ENDLESSDOORS Is Phoning Home. Pick Up.

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Aisuru"
  condition:
    hash.sha256(0, filesize) == "00a1228648fffa7338076970037b89f679a166a08c4d9573f1f27973ec6ed497" or
    hash.sha256(0, filesize) == "09ed9ad3ac886f5aaf8357127b6dd5926bd4af1e2cc687a6a4856bcaedee2667" or
    hash.sha256(0, filesize) == "1545169fa8a3ae182d8e39aca8ec6cb6849b864e38646f29017232813e397e77" or
    hash.sha256(0, filesize) == "2d558bc9a6c7e7480e946f1c0524a651554887a1c563d7633f1903d06ff493fb" or
    hash.sha256(0, filesize) == "31ee58a134b766f6ed4424a22cc2cb08cfabbc9a5f35e0ae11a250c81ccc7f5e" or
    hash.sha256(0, filesize) == "33f8c0532100eeb10213d167e5eb483394a7e43bf6d276441a1573360622011a" or
    hash.sha256(0, filesize) == "37efadf0f4a110be0145139a43ebd032abb5b27b79b1eb2ab3578dcd31655a9e" or
    hash.sha256(0, filesize) == "47d8ffb3a9a3fe0337e3c1e355fab4847dd61952fbe9aad98aadede489ca31fd" or
    hash.sha256(0, filesize) == "4f5d8319b4bad5d9243496c1358fda4783ea9a0865c32881b3f57ecedb879570" or
    hash.sha256(0, filesize) == "6926f919da7f4447229f49842266d884369e1587df655149673e46f1d8787e47" or
    hash.sha256(0, filesize) == "71b20ebff0630b33c96bef320adc75901b34f1fd2cc9af974cf93ff37d102ec8" or
    hash.sha256(0, filesize) == "73a0d95b8e23c7780cd91e978238c6db519665b05481fb228b4db9a9ec99c8ae" or
    hash.sha256(0, filesize) == "76a17581bbde4c0550e8f4abfd903923aceeb50dc69dae4dd904628c273b90ee" or
    hash.sha256(0, filesize) == "7791de11cd27cb596deff089904a6eab3a7e0aa391f867c2389582d5c78fef4c" or
    hash.sha256(0, filesize) == "ab8467e1495479693f4de8e838a5aeb61a65f3682d68f5b2d7c856cbfc91a247" or
    hash.sha256(0, filesize) == "b3956cfbebf9c8d0b2c7a2ecbe59e71c31a5802f2084d25d93a984c0f811e2c7" or
    hash.sha256(0, filesize) == "b3e667235e9b41b8fc3594edaa64879750e7f75d7518fff7514d55837430411a" or
    hash.sha256(0, filesize) == "b4fda77e082fbf961db02273999e92e715e1824140ea92b2ab30163338b6622b" or
    hash.sha256(0, filesize) == "dc1f4056af20677bdc7294ae4707f0c7bdfc85d8b57db212b622b9dc09c92731" or
    hash.sha256(0, filesize) == "dcdaa1fe80707b8d8fde8ad36c3e62a53623aff09bf5ccc544d4c1a1a54208b8" or
    hash.sha256(0, filesize) == "dee3908280b91cb7ad60c69c1d34c599ceed7c8c66c025851e5831482815b271" or
    hash.sha256(0, filesize) == "e85104fce4061d52d47f4528df9aaf656edc49f05c0f026c5bc6b65d57eb7f22" or
    hash.sha256(0, filesize) == "efc8a8ead69c63ecfffd883cfbe6bd131082aa13c0d3b324c00d79f4c149bd92" or
    hash.sha256(0, filesize) == "f019d03c2489b2bc486d71e355e07f8f2862dff078574a8662a5a45932e7e453" or
    hash.sha256(0, filesize) == "f5a94e536a1cac8552fb9c327c4bac6017e034786be98cc402a149cb51250d8f" or
    hash.sha256(0, filesize) == "f961e4243e759453294340bc7d1b145016d70b97ab328caf47c64ea3cd818148" or
    hash.sha1(0, filesize) == "df1ae1a109b329689a1eb3d1bd9bd1e9ed247cfd"
}
