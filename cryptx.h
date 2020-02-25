#pragma once
#include "pch.h"

#ifdef CRYPTX_EXPORTS
#define CRYPTX_API __declspec(dllexport)
#else
#define CRYPTX_API __declspec(dllimport)
#endif

typedef const int CRYPTX_CRYPTO_METHOD;
typedef const int CRYPTX_ENUM;

/*******************************************
cryptX cryptographic methods
*******************************************/
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_MD2              = -1;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_MD4              = 0;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_MD5              = 1;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA              = 3;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA256           = 4;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA384           = 41;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA512           = 5;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA3_256         = 51;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA3_384         = 52;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA3_512         = 53;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_BLAKE2B          = 6;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_RIPEMD           = 7;

extern CRYPTX_API CRYPTX_CRYPTO_METHOD KEY_HASH_HMAC         = 8;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD KEY_HASH_GMAC         = 9;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD KEY_HASH_POLY1305     = 10;

extern CRYPTX_API CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_AES128   = 11;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_DES      = 12;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_DES3     = 13;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_CAMELLIA = 14;

extern CRYPTX_API CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_ARC4   = 15;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_RABBIT = 16;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_HC128  = 17;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_CHACHA = 18;

extern CRYPTX_API CRYPTX_ENUM CRYPTX_MD2_DIGEST              = 16;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_MD4_DIGEST              = 16;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_MD5_DIGEST              = 16;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA_DIGEST              = 20;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA256_DIGEST           = 32;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA384_DIGEST           = 48;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA512_DIGEST           = 64;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA3256_DIGEST          = 32;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA3384_DIGEST          = 48;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA3512_DIGEST          = 64;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_BLAKE2_DIGEST           = 64;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_RIPEMD_DIGEST           = 20;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_POLY1305_DIGEST         = 16;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_AES_BLOCK               = 16;

extern CRYPTX_API CRYPTX_ENUM CRYPTX_SUCCESS                 = 0;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_FAIL                    = -1;

class CRYPTX_API cryptx
{
public:
    cryptx(byte data[], int datasz) { memcpy(this->buffer, data, datasz); }
    ~cryptx();

    void* FormCryptoAgent(CRYPTX_CRYPTO_METHOD x);

    void* UpdateBuffer(CRYPTX_CRYPTO_METHOD type, const byte data[], int datasz);
    void* Hash(CRYPTX_CRYPTO_METHOD type);
    byte* getDigest(CRYPTX_CRYPTO_METHOD type);

protected:
    byte buffer[1024];

    class MD2x;
    class MD4x;
    class MD5x;
    class SHAx;
    class SHA256x;
    class SHA384x;
    class SHA512x;
    class Blake2Bx;
    class RipeMDx;

    MD2x* md2cat = nullptr;
    MD4x* md4cat = nullptr;
    MD5x* md5cat = nullptr;
    SHAx* shacat = nullptr;
    SHA256x* sha256cat = nullptr;
    SHA384x* sha384cat = nullptr;
    SHA512x* sha512cat = nullptr;
    Blake2Bx* blake2bcat = nullptr;
    RipeMDx* ripemdcat = nullptr;
};

class cryptx::MD2x
{
public:
	MD2x(byte data[], int datasz) {
		ZeroMemory(this->buffer, 1024);
		memcpy(this->buffer, data, datasz);
		wc_InitMd2(&md4z);
	}

	void* UpdateBuffer(const byte data[], int datasz);
	void* Hash();
	byte* getDigest();
protected:
	Md2 md4z;

	byte digest[CRYPTX_MD2_DIGEST];
	byte buffer[1024];
};

class cryptx::MD4x
{
public:
	MD4x(byte data[], int datasz) {
		ZeroMemory(this->buffer, 1024);
		memcpy(this->buffer, data, datasz);
		wc_InitMd4(&md4z);
	}

	void* UpdateBuffer(const byte data[], int datasz);
	void* Hash();
	byte* getDigest();
protected:
	Md4 md4z;

	byte digest[CRYPTX_MD4_DIGEST];
	byte buffer[1024];
};

class cryptx::MD5x
{
public:
	MD5x(byte data[], int datasz) {
		ZeroMemory(this->buffer, 1024);
		memcpy(this->buffer, data, datasz);
		wc_InitMd5(&md4z);
	};

	void* UpdateBuffer(const byte data[], int datasz);
	void* Hash();
	byte* getDigest();
protected:
	Md5 md4z;

	byte digest[CRYPTX_MD5_DIGEST];
	byte buffer[1024];
};

class cryptx::SHAx
{
public:
	SHAx(byte data[], int datasz) {
		ZeroMemory(this->buffer, 1024);
		memcpy(this->buffer, data, datasz);
		wc_InitSha(&shaz);
	};

	void* UpdateBuffer(const byte data[], int datasz);
	void* Hash();
	byte* getDigest();
protected:
	Sha shaz;

	byte digest[CRYPTX_SHA_DIGEST];
	byte buffer[1024];
};

class cryptx::SHA256x
{
public:
	SHA256x(byte data[], int datasz) {
		ZeroMemory(this->buffer, 1024);
		memcpy(this->buffer, data, datasz);
		wc_InitSha256(&shaz);
	};

	void* UpdateBuffer(const byte data[], int datasz);
	void* Hash();
	byte* getDigest();
protected:
	Sha256 shaz;

	byte digest[CRYPTX_SHA256_DIGEST];
	byte buffer[1024];
};

class cryptx::SHA384x
{
public:
	SHA384x(byte data[], int datasz) {
		ZeroMemory(this->buffer, 1024);
		memcpy(this->buffer, data, datasz);
		wc_InitSha384(&shaz);
	};

	void* UpdateBuffer(const byte data[], int datasz);
	void* Hash();
	byte* getDigest();
protected:
	Sha384 shaz;

	byte digest[CRYPTX_SHA384_DIGEST];
	byte buffer[1024];
};

class cryptx::SHA512x
{
public:
	SHA512x(byte data[], int datasz) {
		ZeroMemory(this->buffer, 1024);
		memcpy(this->buffer, data, datasz);
		wc_InitSha512(&shaz);
	};

	void* UpdateBuffer(const byte data[], int datasz);
	void* Hash();
	byte* getDigest();
protected:
	Sha512 shaz;

	byte digest[CRYPTX_SHA512_DIGEST];
	byte buffer[1024];
};

class cryptx::Blake2Bx
{
public:
	Blake2Bx(byte data[], int datasz) {
		ZeroMemory(this->buffer, 1024);
		memcpy(this->buffer, data, datasz);
		wc_InitBlake2b(&b2bx, sizeof(data));
	};

	void* UpdateBuffer(const byte data[], int datasz);
	void* Hash();
	byte* getDigest();
protected:
	Blake2b b2bx;

	byte digest[CRYPTX_BLAKE2_DIGEST];
	byte buffer[1024];
};

class cryptx::RipeMDx
{
public:
	RipeMDx(byte data[], int datasz) {
		ZeroMemory(this->buffer, 1024);
		memcpy(this->buffer, data, datasz);
		wc_InitRipeMd(&rmbx);
	};

	void* UpdateBuffer(const byte data[], int datasz);
	void* Hash();
	byte* getDigest();
protected:
	RipeMd rmbx;

	byte digest[CRYPTX_RIPEMD_DIGEST];
	byte buffer[1024];
};