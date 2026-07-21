import "hash"
// Salamander CTI  //  https://salacti.com
// HOLLOWGRAPH: Turning Microsoft 365 Calendars into Covert Command-and-Control Channels

rule Salamander_LYCEUM
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "LYCEUM"
    malware = "HOLLOWGRAPH, Cavern"
  condition:
    hash.sha256(0, filesize) == "315bdba98c6fe863d39f6afccc727e17d5aea63bf21259444fa988cae56d61c1" or
    hash.sha256(0, filesize) == "1573e125197ec77d8e9930c611ba2802ee59e19629396b5e99b426b46c53bd25" or
    hash.sha256(0, filesize) == "75e51774b8f79e5f256eaae639635f911b3e744d4774fd6068dd980255621509" or
    hash.sha256(0, filesize) == "b3d0f6e4e3be395fd7cf9e8101c89963d77216578cbb117a6ac9bc3564485eff" or
    hash.sha256(0, filesize) == "f3f3006f8304788251b153d53b305322b8acab0c66ec816b8d9f101bcc851da3"
}
