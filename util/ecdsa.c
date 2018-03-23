// using figures on: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
// gcc -Wall ecdsapubkey.c -o ecdsapubkey -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <assert.h>

#include <openssl/pem.h>

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

char* Base64Decode(char* b64message) {
	int decodeLen = calcDecodeLength(b64message);

	BIO* bio = BIO_new_mem_buf(b64message, -1);
	BIO* b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer

	char* buffer = (unsigned char*)malloc(decodeLen + 1);
	size_t length = BIO_read(bio, buffer, strlen(b64message));
	assert(length == decodeLen); // check nothing went horribly wrong
	buffer[decodeLen] = '\0';
	BIO_free_all(bio);

	return buffer;
}

char* bin2hex(const unsigned char *bin)
{
	int len = strlen(bin);
    if (bin == NULL || len == 0)
        return NULL;

    char* hex = malloc(len*2+1);
    for (int i=0; i < len; i++) {
        hex[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
        hex[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
    }
    hex[len*2] = '\0';
	return hex;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Enter private key parameter\n");
		return 1;
	}

	// BASE64 private key to hex
	unsigned char* encoded_privkey = Base64Decode(argv[1]);
	char* hex_privkey = bin2hex(encoded_privkey);
	free(encoded_privkey);
	printf("Private key: %s\n\n", hex_privkey);


	// Set up ECC key
	BN_CTX* ctx = BN_CTX_new(); // ctx is an optional buffer to save time from allocating and deallocating memory whenever required
	BIGNUM *res = BN_new();
	BN_hex2bn(&res, hex_privkey);

	EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	const EC_GROUP* group = EC_KEY_get0_group(eckey);
	EC_POINT* pub_key = EC_POINT_new(group);

	EC_KEY_set_private_key(eckey, res);

	// pub_key is a new uninitialized `EC_POINT*`
	// priv_key res is a `BIGNUM*`
	if (!EC_POINT_mul(group, pub_key, res, NULL, NULL, ctx))
		printf("Error at EC_POINT_mul.\n");
	EC_KEY_set_public_key(eckey, pub_key);


	// Convert ECC key to EVP_PKEY
	EVP_PKEY* ossl_pkey = EVP_PKEY_new();
	if (!EVP_PKEY_set1_EC_KEY(ossl_pkey, eckey))
	{
		fprintf(stderr, "ERROR: Could not convert EC key to EVP_PKEY.\n");
		EC_KEY_free(eckey);
		EVP_PKEY_free(ossl_pkey);
		return 1;
	}
	EC_KEY_free(eckey);

	// Get the privkey PEM form: */
	BIO* outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
	PEM_write_bio_PrivateKey_traditional(outbio, ossl_pkey, NULL, NULL, 0, NULL, NULL);
	BIO_free_all(outbio);

	char *cc = EC_POINT_point2hex(group, pub_key, 4, ctx);
	BN_CTX_free(ctx);

	printf("\nPublic key: %s\n", cc);
	free(cc);

	return 0;
}
