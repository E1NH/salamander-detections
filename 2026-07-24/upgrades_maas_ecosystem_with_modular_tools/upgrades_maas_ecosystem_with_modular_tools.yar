import "hash"
// Salamander CTI  //  https://salacti.com
// Upgrades MaaS Ecosystem with Modular Tools

rule Salamander_TAG_195
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TAG-195"
    malware = "ChromElevator, Unknown malware, VenomLoader"
  condition:
    hash.sha256(0, filesize) == "6c23b7723a9f69ea48f02c8fe13fd60ecbfc2fb28e32e481c46ec968a66c66cd" or
    hash.sha256(0, filesize) == "b7b322f4638ead5c39031ffc7ca8c791c8d47211b09449f7ceb49f0c32a19b45" or
    hash.sha256(0, filesize) == "45c8cbaeb5c7708e7b8030e701747c65203958e82eddc41f39e0ca93bd36c114" or
    hash.sha256(0, filesize) == "d2e1ab10d5a0c16a724aeda8acb46b38f551ade58137969c3bc3c9cdc0a12425" or
    hash.sha256(0, filesize) == "5cae5202ddcc29f19f954d81ba138f11b8a4080d05fef63c05a00b9242c06967" or
    hash.sha256(0, filesize) == "9a2d714ddd5c48722c35df8a70e97f12d46bcde05dc79b7242a7e692bd346826" or
    hash.sha256(0, filesize) == "6c7619c34497f430c4f7618cfefe07d1defacfae48f6730c20f52e7a7344faa9" or
    hash.sha256(0, filesize) == "41aa04782e436345ef45dc159321d5c0e0e5cba300e55a4d1d3194e5c7c5fd97" or
    hash.sha256(0, filesize) == "d5dea9a51b984be9d7fa76e3e8ff89cfb97c335927331e8e348b9ee269070c1b" or
    hash.sha256(0, filesize) == "16735cb80d796865b2430aa11d21a539fcb00b027932f2c63e4b5c098d26585b" or
    hash.sha256(0, filesize) == "e3153ced59bb0376186b0eee0ec68f0b5aa9ae5820ef8508ae4e67625e1a3581" or
    hash.sha256(0, filesize) == "6922b319dc96d020738bcf466c4d6d9233e4767b68592e1fd9258a232f166ce1" or
    hash.md5(0, filesize) == "03713176e7f0d9f3b37ac6eb644d90bb" or
    hash.md5(0, filesize) == "210f57e3b1c88447ddc11467f7b2fbb9" or
    hash.md5(0, filesize) == "2cc1ec080f7e1fcd2c0c6ae033b988c5" or
    hash.md5(0, filesize) == "2cf627a0a9d64db3e4cd13fda3ce5636" or
    hash.md5(0, filesize) == "3418b6439309250feb2cd983aa00da44" or
    hash.md5(0, filesize) == "396d4f44e429e7128af9c02e0c1bdf99" or
    hash.md5(0, filesize) == "552d991cccd6c5053dfda46c0ac32623" or
    hash.md5(0, filesize) == "60992cdeb88dddfb17e12573e4436c42" or
    hash.md5(0, filesize) == "70983540817fd9ff46204001a7b35ba0" or
    hash.md5(0, filesize) == "7a0edeb5bebc51de8ce455f38d9a7670" or
    hash.md5(0, filesize) == "7c6e4a085b1fd9b98407ba4400f91201" or
    hash.md5(0, filesize) == "8ea54a900bd13ff3ecca01e62428e508" or
    hash.md5(0, filesize) == "960688e3484eb744cdbbee55a7415bd1" or
    hash.md5(0, filesize) == "9bd6f7a308418a2b376e731d9e80bac1" or
    hash.md5(0, filesize) == "9d6f7697c0fbea55d6bfb39642eb87df" or
    hash.md5(0, filesize) == "c21f69bbf1f78ebf4f1aa784cee035ce" or
    hash.md5(0, filesize) == "cbe0daeec71e47840672d930e112d467" or
    hash.md5(0, filesize) == "e4ee5ed330eaa0602f4f637f5567d08e" or
    hash.md5(0, filesize) == "f23cb60ab395cc6bf931eed16b801ed7" or
    hash.sha1(0, filesize) == "06eade11e16465edef89ba0199d7d6f8c18a3200" or
    hash.sha1(0, filesize) == "10f6effed5a4dfff9b6e94ea90bc2134510f770f" or
    hash.sha1(0, filesize) == "26545d3db9802c44145e289b8e989d0a68bf90cb" or
    hash.sha1(0, filesize) == "2b57771989fc059bbef8f28fc0ca24eeae7e7863" or
    hash.sha1(0, filesize) == "39b3b4bb7a1b45cc155e0f8a7149df393e98b2b6" or
    hash.sha1(0, filesize) == "3a0257f31f8db0bf5e1526f4c65f79808e4a5eea" or
    hash.sha1(0, filesize) == "3ea1ccbd98c3fa8ed5cc23642ef5db39e900d88b" or
    hash.sha1(0, filesize) == "49d8bcb15cbf235a1a5f5d81a5ed4e1045b2d90a" or
    hash.sha1(0, filesize) == "5c50a13f91b0c5a109c96628e2e35f86a2c3d6c3" or
    hash.sha1(0, filesize) == "6a29c8ebd0c77e5655c39963df9c86ca9c145d08" or
    hash.sha1(0, filesize) == "72e488857a6c6c659c0c673f0e4c32a610ea41ee" or
    hash.sha1(0, filesize) == "7df85059c75bcd3e6280b4c60e1d75c094429664" or
    hash.sha1(0, filesize) == "813cd8a638b4d5cde58bdf8df7c02260a404802c" or
    hash.sha1(0, filesize) == "b5b0993b33d65f14a357b4f371d2093238c0e9d0" or
    hash.sha1(0, filesize) == "c5d8601c7b65a584696fe63e8817b395414bc1ed" or
    hash.sha1(0, filesize) == "c6c299162eae50a1d76ee9f6d42f60cef464fa04" or
    hash.sha1(0, filesize) == "d48d1a4dfb6d015df1ee019ea70ec59137c4b948" or
    hash.sha1(0, filesize) == "d810f563443e8f11478937bfcf20ff178d45eedb" or
    hash.sha1(0, filesize) == "e6b4511b53ed8ef7c857c236a5907d077862f7ad" or
    hash.sha256(0, filesize) == "086273cd91f3d6556ed2af915df310e4b184b3db84c3903aa09830d49d1fbb62" or
    hash.sha256(0, filesize) == "200fbc76bd9fab3b4adcecfe44233cf47146f5709a9735a0232cb4aa7284eadb" or
    hash.sha256(0, filesize) == "3250adbca0a0bfeab8bd88ee93b603be31fc86b341fd77a152b4843416560d53" or
    hash.sha256(0, filesize) == "337e92c233edc38842c6122fa38e0e84a478f5aa5af2a95ca6be3ca056d925b8" or
    hash.sha256(0, filesize) == "33a12c2328db22429c4a515400a57ffeaf7aec48a2a3c299ab6f1ce2d2b0e87d"
}
