#include <openssl/evp.h>
#include <openssl/rsa.h>

/* EVP_md5() 은 쓰지 않는다 */
// EVP_des_ede3_cbc() 도 금지
static const char *doc = "EVP_sha1() 예제";
static int md5_count = 0;

void run(EVP_MD_CTX *ctx, EVP_CIPHER_CTX *c) {
    /* 옛 코드 */ EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestInit(ctx, EVP_md5());
    EVP_EncryptInit(c, EVP_aes_128_cbc(), 0, 0);
    EVP_EncryptInit(c, EVP_des_ede3_cbc(), 0, 0);
    RSA_generate_key_ex(rsa_key, 2048, e, NULL);
}
