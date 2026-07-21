import "hash"
// Salamander CTI  //  https://salacti.com
// Analysis of Ongoing Ousaban Attacks Targeting the Iberian Peninsula

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "RustyStealer"
  condition:
    hash.sha256(0, filesize) == "d4eb4ff02df659fdeec17d36b77084627469623bb3c7d16383d257404b52d1c3" or
    hash.md5(0, filesize) == "18205d398e5df7d38705dbdc700ccb46" or
    hash.md5(0, filesize) == "22e3cd043e36a9c0bad1479ad4c3214a" or
    hash.md5(0, filesize) == "26c0aee6c79935ee6da46e6444f1c109" or
    hash.md5(0, filesize) == "ebb680f7ae4db6cdc426b8112d2536b6" or
    hash.sha1(0, filesize) == "11ca4e19ea79f68aaf23c4afe472dbc03833002c" or
    hash.sha1(0, filesize) == "1ec576cf0c82c023f2eb380809588980b98cd296" or
    hash.sha1(0, filesize) == "26b9b123e0f664dd9792b820255fe991496cf2d6" or
    hash.sha1(0, filesize) == "6e37b4a0c1d747d19abb6736a1ec3293972d3e0f" or
    hash.sha256(0, filesize) == "18fd38988d58dd930f5992d448cc09a9400c1eafba76b820b9a83239ac48cf4e" or
    hash.sha256(0, filesize) == "19ac18a50abb48dc0ea9524850acfaec49359e6b3bcc67c6193c2d56da812c71" or
    hash.sha256(0, filesize) == "1e77992666acbbfa0d01fcefa9cc8fbdac291e0681b35745be27c6dfb159a375" or
    hash.sha256(0, filesize) == "21b24f7ee1f6bdbbb670f0394d66009ee0daa8ced57048298da715e88f7a7cdd" or
    hash.sha256(0, filesize) == "48723a33bab89f174750576f9a62da35b3b9e5ac31a5a8f1ce9859a1b35bf8b8" or
    hash.sha256(0, filesize) == "4c9fdc2823da505ef339d43c6ad38499b7e3447736733e42b5ab6b1afcfd42aa" or
    hash.sha256(0, filesize) == "4ca2c863d740bb7022776dccabd8ae34bb9998768928042d76ebcf08984eefcb" or
    hash.sha256(0, filesize) == "540ee1936e61d2344b5ebc93485589a351ec2f113a9b4940ae16f3baa4807392" or
    hash.sha256(0, filesize) == "5837e47198a20877e1b04b270c36d9194206ee38d4f32fe3151b3c3b396c4f0d" or
    hash.sha256(0, filesize) == "5a2ed557c357ba8f96f2d55a8a00695987806b5df766cd1dfdab0cbed111774a" or
    hash.sha256(0, filesize) == "5e06af187b45476ade0d953e834fced6197d0a33ac60c2575877660e26ab15e8" or
    hash.sha256(0, filesize) == "65c1a998bac48e02b52b1c850cd500e9fb87521e21755c3a4a491243f5f9a700" or
    hash.sha256(0, filesize) == "6bc2e11b0917f47d0557288c4f0cb20bd7589185943b989a969fdc6d3704ee73" or
    hash.sha256(0, filesize) == "9d07a83cf89685651ea8992047ae694c24f6ddef193044357debd15ce07a64fe" or
    hash.sha256(0, filesize) == "9e81ade09cc18f0fc09d73e72d2e0bffad02f52fdcc26553e473cee8cabc1567" or
    hash.sha256(0, filesize) == "e2f0c2d4c1552cd81fa012043e4a5ac832582b639b7b6b7eccc0c4802d7a8ad8" or
    hash.sha256(0, filesize) == "e6e78eb2e9bd41a4bc62f7ad54d095ea9813864bebe37172ae30a1afa631fe14" or
    hash.sha256(0, filesize) == "fadbb8061715128bebecf7bc59132b6bb04fe8cc39b965aa5b8722dffe28d7e7" or
    hash.sha256(0, filesize) == "ffb9eb47cc0cb2f43e04a10dc84df13d04bca1ebacbe47fad0b669728de2f59c"
}
