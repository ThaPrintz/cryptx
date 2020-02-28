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
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_MD2;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_MD4;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_MD5;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA256;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA384;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA512;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA3_256;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA3_384;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_SHA3_512;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_BLAKE2B;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD HASH_RIPEMD;
														
extern CRYPTX_API CRYPTX_CRYPTO_METHOD KEY_HASH_HMAC    ;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD KEY_HASH_GMAC    ;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD KEY_HASH_POLY1305;
															;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_AES128  ;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_DES     ;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_DES3    ;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_CAMELLIA;
															;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_ARC4  ;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_RABBIT;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_HC128 ;
extern CRYPTX_API CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_CHACHA;
															;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_MD2_DIGEST             ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_MD4_DIGEST             ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_MD5_DIGEST             ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA_DIGEST             ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA256_DIGEST          ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA384_DIGEST          ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA512_DIGEST          ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA3256_DIGEST         ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA3384_DIGEST         ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SHA3512_DIGEST         ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_BLAKE2_DIGEST          ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_RIPEMD_DIGEST          ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_POLY1305_DIGEST        ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_AES_BLOCK              ;
															;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_SUCCESS                ;
extern CRYPTX_API CRYPTX_ENUM CRYPTX_FAIL                   ;

class CRYPTX_API cryptx
{
public:
	cryptx(byte data[], int datasz) { memcpy(this->buffer, data, datasz); }
	~cryptx();

	void* FormCryptoAgent(CRYPTX_CRYPTO_METHOD x);

	void* UpdateBuffer(CRYPTX_CRYPTO_METHOD type, const byte data[], int datasz);

	void* SetKey(CRYPTX_CRYPTO_METHOD x, const byte key[], int keysz);
	void* SetIV(CRYPTX_CRYPTO_METHOD x, const byte key[], int keysz);

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

	class HMACx;
	class GMACx;
	class Poly1305x;

	MD2x* md2cat = nullptr;
	MD4x* md4cat = nullptr;
	MD5x* md5cat = nullptr;
	SHAx* shacat = nullptr;
	SHA256x* sha256cat = nullptr;
	SHA384x* sha384cat = nullptr;
	SHA512x* sha512cat = nullptr;
	Blake2Bx* blake2bcat = nullptr;
	RipeMDx* ripemdcat = nullptr;

	HMACx* hmaccat = nullptr;
	GMACx* gmaccat = nullptr;
	Poly1305x* polycat = nullptr;
};


/******************
MD2
******************/
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

/******************
MD4
******************/
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

/******************
MD5
******************/
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

/******************
SHA
******************/
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

/******************
SHA256
******************/
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

/******************
SHA384
******************/
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

/******************
SHA512
******************/
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

/******************
Blake2B
******************/
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

/******************
RipeMD-160
******************/
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

/******************
HMAC
******************/
class cryptx::HMACx
{
public:
	HMACx(byte data[], int datasz)
	{
		ZeroMemory(this->buffer, 2048);
		memcpy(this->buffer, data, datasz);
	}

	void* UpdateBuffer(const byte data[], int datasz);
	void* SetKey(const byte key[], int keysz);

	void* Hash(CRYPTX_CRYPTO_METHOD type);
	byte* getDigest(CRYPTX_CRYPTO_METHOD type);
protected:
	Hmac hmac;

	byte md5digest[CRYPTX_MD5_DIGEST];
	byte shadigest[CRYPTX_SHA_DIGEST];
	byte sha256digest[CRYPTX_SHA256_DIGEST];
	byte sha384digest[CRYPTX_SHA384_DIGEST];
	byte sha512digest[CRYPTX_SHA512_DIGEST];

	byte key[24];
	byte buffer[2048];
};

/******************
GMAC
******************/
class cryptx::GMACx
{
public:
	GMACx(byte data[], int datasz)
	{
		ZeroMemory(this->buffer, 2048);
		memcpy(this->buffer, data, datasz);
	}

	void* UpdateBuffer(const byte data[], int datasz);
	void* SetKey(const byte key[], int keysz);
	void* SetIV(const byte niv[], int ivsz);

	void* Hash();
	byte* getDigest();
protected:
	Gmac gmac;

	byte digest[CRYPTX_AES_BLOCK];

	byte key[16];
	byte iv[12];
	byte buffer[2048];
};

/******************
Poly1305
******************/
class cryptx::Poly1305x
{
public:
	Poly1305x(byte data[], int datasz)
	{
		ZeroMemory(this->buffer, 2048);
		memcpy(this->buffer, data, datasz);
	}

	void* UpdateBuffer(const byte data[], int datasz);
	void* SetKey(const byte nkey[], int keysz);

	void* Hash();
	byte* getDigest();
protected:
	Poly1305 poly;

	byte digest[CRYPTX_POLY1305_DIGEST];
	byte buffer[2048];
	byte key[32];
};