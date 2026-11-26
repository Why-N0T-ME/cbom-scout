using System.Security.Cryptography;

class Crypto
{
    // var old = MD5.Create();
    /* TripleDES.Create() 금지 */
    string doc = @"SHA1.Create() ""예제""";
    string msg = "DES.Create() 는 쓰지 않는다";
    int md5Count = 0;

    void Run()
    {
        var a = MD5.Create();
        var b = SHA1.Create();
        var c = SHA256.Create();
        var d = TripleDES.Create();
        var e = RSA.Create();
        var f = Aes.Create();
    }
}
