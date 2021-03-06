#include "pch.h"

CRYPTX_CRYPTO_METHOD HASH_MD2 = -1;
CRYPTX_CRYPTO_METHOD HASH_MD4 = 0;
CRYPTX_CRYPTO_METHOD HASH_MD5 = 1;
CRYPTX_CRYPTO_METHOD HASH_SHA = 3;
CRYPTX_CRYPTO_METHOD HASH_SHA256 = 4;
CRYPTX_CRYPTO_METHOD HASH_SHA384 = 41;
CRYPTX_CRYPTO_METHOD HASH_SHA512 = 5;
CRYPTX_CRYPTO_METHOD HASH_SHA3_256 = 51;
CRYPTX_CRYPTO_METHOD HASH_SHA3_384 = 52;
CRYPTX_CRYPTO_METHOD HASH_SHA3_512 = 53;
CRYPTX_CRYPTO_METHOD HASH_BLAKE2B = 6;
CRYPTX_CRYPTO_METHOD HASH_RIPEMD = 7;

CRYPTX_CRYPTO_METHOD KEY_HASH_HMAC = 8;
CRYPTX_CRYPTO_METHOD KEY_HASH_GMAC = 9;
CRYPTX_CRYPTO_METHOD KEY_HASH_POLY1305 = 10;

CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_AES128 = 11;
CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_DES = 12;
CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_DES3 = 13;
CRYPTX_CRYPTO_METHOD BLOCK_CIPHER_CAMELLIA = 14;

CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_ARC4 = 15;
CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_RABBIT = 16;
CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_HC128 = 17;
CRYPTX_CRYPTO_METHOD  STREAM_CIPHER_CHACHA = 18;

/******************
MD2
******************/
void* cryptx::MD2x::Hash()
{
	ZeroMemory(this->digest, CRYPTX_MD2_DIGEST);

	wc_Md2Update(&this->md4z, this->buffer, strlen((const char*)this->buffer));
	wc_Md2Final(&this->md4z, this->digest);

	return nullptr;
}

void* cryptx::MD2x::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::MD2x::getDigest()
{
	return this->digest;
}

/******************
MD4
******************/
void* cryptx::MD4x::Hash()
{
	ZeroMemory(this->digest, CRYPTX_MD4_DIGEST);

	wc_Md4Update(&this->md4z, this->buffer, strlen((const char*)this->buffer));
	wc_Md4Final(&this->md4z, this->digest);

	return nullptr;
}

void* cryptx::MD4x::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::MD4x::getDigest()
{
	return this->digest;
}

/******************
MD5
******************/
void* cryptx::MD5x::Hash()
{
	ZeroMemory(this->digest, CRYPTX_MD5_DIGEST);

	wc_Md5Update(&this->md4z, this->buffer, strlen((const char*)this->buffer));
	wc_Md5Final(&this->md4z, this->digest);

	return nullptr;
}

void* cryptx::MD5x::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::MD5x::getDigest()
{
	return this->digest;
}

/******************
SHA
******************/
void* cryptx::SHAx::Hash()
{
	ZeroMemory(this->digest, CRYPTX_SHA_DIGEST);

	wc_ShaUpdate(&this->shaz, this->buffer, strlen((const char*)this->buffer));
	wc_ShaFinal(&this->shaz, this->digest);

	return nullptr;
}

void* cryptx::SHAx::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::SHAx::getDigest()
{
	return this->digest;
}

/******************
SHA256
******************/
void* cryptx::SHA256x::Hash()
{
	ZeroMemory(this->digest, CRYPTX_SHA256_DIGEST);

	wc_Sha256Update(&this->shaz, this->buffer, strlen((const char*)this->buffer));
	wc_Sha256Final(&this->shaz, this->digest);

	return nullptr;
}

void* cryptx::SHA256x::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::SHA256x::getDigest()
{
	return this->digest;
}

/******************
SHA384
******************/
void* cryptx::SHA384x::Hash()
{
	ZeroMemory(this->digest, CRYPTX_SHA384_DIGEST);

	wc_Sha384Update(&this->shaz, this->buffer, strlen((const char*)this->buffer));
	wc_Sha384Final(&this->shaz, this->digest);

	return nullptr;
}

void* cryptx::SHA384x::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::SHA384x::getDigest()
{
	return this->digest;
}

/******************
SHA512
******************/
void* cryptx::SHA512x::Hash()
{
	ZeroMemory(this->digest, CRYPTX_SHA512_DIGEST);

	wc_Sha512Update(&this->shaz, this->buffer, strlen((const char*)this->buffer));
	wc_Sha512Final(&this->shaz, this->digest);

	return nullptr;
}

void* cryptx::SHA512x::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::SHA512x::getDigest()
{
	return this->digest;
}

/******************
Blake2B
******************/
void* cryptx::Blake2Bx::Hash()
{
	ZeroMemory(this->digest, CRYPTX_BLAKE2_DIGEST);

	wc_Blake2bUpdate(&this->b2bx, this->buffer, strlen((const char*)this->buffer));
	wc_Blake2bFinal(&this->b2bx, this->digest, CRYPTX_BLAKE2_DIGEST);

	return nullptr;
}

void* cryptx::Blake2Bx::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::Blake2Bx::getDigest()
{
	return this->digest;
}

/******************
RipeMD-160
******************/
void* cryptx::RipeMDx::Hash()
{
	ZeroMemory(this->digest, CRYPTX_RIPEMD_DIGEST);

	wc_RipeMdUpdate(&this->rmbx, this->buffer, strlen((const char*)this->buffer));
	wc_RipeMdFinal(&this->rmbx, this->digest);

	return nullptr;
}

void* cryptx::RipeMDx::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::RipeMDx::getDigest()
{
	return this->digest;
}

/******************
HMAC
******************/
void* cryptx::HMACx::Hash(CRYPTX_CRYPTO_METHOD type)
{
	if (type == HASH_MD5)
	{
		ZeroMemory(this->md5digest, CRYPTX_MD5_DIGEST);

		wc_HmacSetKey(&this->hmac, MD5, this->key, sizeof(this->key));
		wc_HmacUpdate(&this->hmac, this->buffer, strlen((const char*)this->buffer));
		wc_HmacFinal(&this->hmac, md5digest);
	} else if (type == HASH_SHA)
	{
		ZeroMemory(this->shadigest, CRYPTX_SHA_DIGEST);

		wc_HmacSetKey(&this->hmac, SHA, this->key, sizeof(this->key));
		wc_HmacUpdate(&this->hmac, this->buffer, strlen((const char*)this->buffer));
		wc_HmacFinal(&this->hmac, shadigest);
	} else if (type == HASH_SHA256)
	{
		ZeroMemory(this->sha256digest, CRYPTX_SHA256_DIGEST);

		wc_HmacSetKey(&this->hmac, SHA256, this->key, sizeof(this->key));
		wc_HmacUpdate(&this->hmac, this->buffer, strlen((const char*)this->buffer));
		wc_HmacFinal(&this->hmac, sha256digest);
	} else if (type == HASH_SHA384)
	{
		ZeroMemory(this->sha384digest, CRYPTX_SHA384_DIGEST);

		wc_HmacSetKey(&this->hmac, SHA384, this->key, sizeof(this->key));
		wc_HmacUpdate(&this->hmac, this->buffer, strlen((const char*)this->buffer));
		wc_HmacFinal(&this->hmac, sha384digest);
	} else if (type == HASH_SHA512)
	{
		ZeroMemory(this->sha512digest, CRYPTX_SHA512_DIGEST);

		wc_HmacSetKey(&this->hmac, SHA512, this->key, sizeof(this->key));
		wc_HmacUpdate(&this->hmac, this->buffer, strlen((const char*)this->buffer));
		wc_HmacFinal(&this->hmac, sha512digest);
	}

	return nullptr;
}

void* cryptx::HMACx::SetKey(const byte nkey[], int keysz)
{
	return memcpy(this->key, nkey, keysz);
}

void* cryptx::HMACx::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::HMACx::getDigest(CRYPTX_CRYPTO_METHOD type)
{
	if (type == HASH_MD5)
	{
		return this->md5digest;
	} else if (type == HASH_SHA)
	{
		return this->shadigest;
	} else if (type == HASH_SHA256)
	{
		return this->sha256digest;
	} else if (type == HASH_SHA384)
	{
		return this->sha384digest;
	} else if (type == HASH_SHA512)
	{
		return this->sha512digest;
	}
}

/******************
GMAC
******************/
void* cryptx::GMACx::Hash()
{
	wc_GmacSetKey(&this->gmac, this->key, sizeof(this->key));
	wc_GmacUpdate(&this->gmac, this->iv, sizeof(this->iv), this->buffer, strlen((const char*)this->buffer), digest, sizeof(digest));

	return nullptr;
}

void* cryptx::GMACx::SetKey(const byte nkey[], int keysz)
{
	return memcpy(this->key, nkey, keysz);
}

void* cryptx::GMACx::SetIV(const byte niv[], int ivsz)
{
	return memcpy(this->iv, niv, ivsz);
}

void* cryptx::GMACx::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::GMACx::getDigest()
{
	return this->digest;
}

/******************
Poly1305
******************/
void* cryptx::Poly1305x::Hash()
{
	wc_Poly1305SetKey(&this->poly, this->key, sizeof(this->key));
	wc_Poly1305Update(&this->poly, this->buffer, strlen((const char*)this->buffer));
	wc_Poly1305Final(&this->poly, digest);

	return nullptr;
}

void* cryptx::Poly1305x::SetKey(const byte nkey[], int keysz)
{
	return memcpy(this->key, nkey, keysz);
}


void* cryptx::Poly1305x::UpdateBuffer(const byte data[], int datasz)
{
	return memcpy(this->buffer, data, datasz);
}

byte* cryptx::Poly1305x::getDigest()
{
	return this->digest;
}

void* cryptx::FormCryptoAgent(CRYPTX_CRYPTO_METHOD x)
{
	if (x == HASH_MD4)
	{
		this->md4cat = new cryptx::MD4x(this->buffer, strlen((const char*)this->buffer));
	} else if (x == HASH_MD2)
	{
		this->md2cat = new cryptx::MD2x(this->buffer, strlen((const char*)this->buffer));
	} else if (x == HASH_MD5)
	{
		this->md5cat = new cryptx::MD5x(this->buffer, strlen((const char*)this->buffer));
	} else if (x == HASH_SHA)
	{
		this->shacat = new cryptx::SHAx(this->buffer, strlen((const char*)this->buffer));
	} else if (x == HASH_SHA256)
	{
		this->sha256cat = new cryptx::SHA256x(this->buffer, strlen((const char*)this->buffer));
	} else if (x == HASH_SHA384)
	{
		this->sha384cat = new cryptx::SHA384x(this->buffer, strlen((const char*)this->buffer));
	} else if (x == HASH_SHA512)
	{
		this->sha512cat = new cryptx::SHA512x(this->buffer, strlen((const char*)this->buffer));
	} else if (x == HASH_BLAKE2B)
	{
		this->blake2bcat = new cryptx::Blake2Bx(this->buffer, strlen((const char*)this->buffer));
	} else if (x == HASH_RIPEMD)
	{
		this->ripemdcat = new cryptx::RipeMDx(this->buffer, strlen((const char*)this->buffer));
	} else if (x == KEY_HASH_HMAC)
	{
		this->hmaccat = new cryptx::HMACx(this->buffer, strlen((const char*)this->buffer));
	} else if (x == KEY_HASH_GMAC)
	{
		this->gmaccat = new cryptx::GMACx(this->buffer, strlen((const char*)this->buffer));
	} else if (x == KEY_HASH_POLY1305)
	{
		this->polycat = new cryptx::Poly1305x(this->buffer, strlen((const char*)this->buffer));
	}
	//else if (x == BLOCK_CIPHER_AES128) {
	//}
	//else if (x == BLOCK_CIPHER_AES192) {
	//}
	//else if (x == BLOCK_CIPHER_AES256) {
	//}
	//else if (x == BLOCK_CIPHER_DES) {
	//}
	//else if (x == BLOCK_CIPHER_DES3) {
	//}
	//else if (x == BLOCK_CIPHER_CAMELLIA) {
	//}
	//else if (x == STREAM_CIPHER_ARC4) {
	//}
	//else if (x == STREAM_CIPHER_RABBIT) {
	//}
	//else if (x == STREAM_CIPHER_HC128) {
	//}
	//else if (x == STREAM_CIPHER_CHACHA) {
	//}

	return nullptr;
}

void* cryptx::SetKey(CRYPTX_CRYPTO_METHOD x, const byte key[], int keysz)
{
	if (x == KEY_HASH_HMAC)
	{
		return this->hmaccat->SetKey(key, keysz);
	} else if (x == KEY_HASH_GMAC)
	{
		return this->gmaccat->SetKey(key, keysz);
	} else if (x == KEY_HASH_POLY1305)
	{
		return this->polycat->SetKey(key, keysz);
	}

	return nullptr;
}

void* cryptx::SetIV(CRYPTX_CRYPTO_METHOD x, const byte key[], int keysz)
{
	if (x == KEY_HASH_GMAC)
	{
		return this->gmaccat->SetIV(key, keysz);
	}

	return nullptr;
}

void* cryptx::UpdateBuffer(CRYPTX_CRYPTO_METHOD x, const byte data[], int datasz)
{
	if (x == HASH_MD4)
	{
		return this->md4cat->UpdateBuffer(data, datasz);
	} else if (x == HASH_MD2)
	{
		return this->md2cat->UpdateBuffer(data, datasz);
	} else if (x == HASH_MD5)
	{
		return this->md5cat->UpdateBuffer(data, datasz);
	} else if (x == HASH_SHA)
	{
		return this->shacat->UpdateBuffer(data, datasz);
	} else if (x == HASH_SHA256)
	{
		return this->sha256cat->UpdateBuffer(data, datasz);
	} else if (x == HASH_SHA384)
	{
		return this->sha384cat->UpdateBuffer(data, datasz);
	} else if (x == HASH_SHA512)
	{
		return this->sha512cat->UpdateBuffer(data, datasz);
	} else if (x == HASH_BLAKE2B)
	{
		return this->blake2bcat->UpdateBuffer(data, datasz);
	} else if (x == HASH_RIPEMD)
	{
		return this->ripemdcat->UpdateBuffer(data, datasz);
	} else if (x == KEY_HASH_HMAC)
	{
		return this->hmaccat->UpdateBuffer(data, datasz);
	} else if (x == KEY_HASH_GMAC)
	{
		return this->gmaccat->UpdateBuffer(data, datasz);
	} else if (x == KEY_HASH_POLY1305)
	{
		return this->polycat->UpdateBuffer(data, datasz);
	}

	return nullptr;
}

void* cryptx::Hash(CRYPTX_CRYPTO_METHOD x)
{
	if (x == HASH_MD4)
	{
		return this->md4cat->Hash();
	} else if (x == HASH_MD2)
	{
		return this->md2cat->Hash();
	} else if (x == HASH_MD5)
	{
		return this->md5cat->Hash();
	} else if (x == HASH_SHA)
	{
		return this->shacat->Hash();
	} else if (x == HASH_SHA256)
	{
		return this->sha256cat->Hash();
	} else if (x == HASH_SHA384)
	{
		return this->sha384cat->Hash();
	} else if (x == HASH_SHA512)
	{
		return this->sha512cat->Hash();
	} else if (x == HASH_BLAKE2B)
	{
		return this->blake2bcat->Hash();
	} else if (x == HASH_RIPEMD)
	{
		return this->ripemdcat->Hash();
	} else if (x == KEY_HASH_HMACMD5)
	{
		return this->hmaccat->Hash(HASH_MD5);
	} else if (x == KEY_HASH_HMACSHA)
	{
		return this->hmaccat->Hash(HASH_SHA);
	} else if (x == KEY_HASH_HMACSHA256)
	{
		return this->hmaccat->Hash(HASH_SHA256);
	} else if (x == KEY_HASH_HMACSHA384)
	{
		return this->hmaccat->Hash(HASH_SHA384);
	} else if (x == KEY_HASH_HMACSHA512)
	{
		return this->hmaccat->Hash(HASH_SHA512);
	} else if (x == KEY_HASH_GMAC)
	{
		return this->gmaccat->Hash();
	} else if (x == KEY_HASH_POLY1305)
	{
		return this->polycat->Hash();
	}

	return nullptr;
}

byte* cryptx::getDigest(CRYPTX_CRYPTO_METHOD x)
{
	if (x == HASH_MD4)
	{
		return this->md4cat->getDigest();
	} else if (x == HASH_MD2)
	{
		return this->md2cat->getDigest();
	} else if (x == HASH_MD5)
	{
		return this->md5cat->getDigest();
	} else if (x == HASH_SHA)
	{
		return this->shacat->getDigest();
	} else if (x == HASH_SHA256)
	{
		return this->sha256cat->getDigest();
	} else if (x == HASH_SHA384)
	{
		return this->sha384cat->getDigest();
	} else if (x == HASH_SHA512)
	{
		return this->sha512cat->getDigest();
	} else if (x == HASH_BLAKE2B)
	{
		return this->blake2bcat->getDigest();
	} else if (x == HASH_RIPEMD)
	{
		return this->ripemdcat->getDigest();
	} else if (x == KEY_HASH_HMACMD5)
	{
		return this->hmaccat->getDigest(HASH_MD5);
	} else if (x == KEY_HASH_HMACSHA)
	{
		return this->hmaccat->getDigest(HASH_SHA);
	} else if (x == KEY_HASH_HMACSHA256)
	{
		return this->hmaccat->getDigest(HASH_SHA256);
	} else if (x == KEY_HASH_HMACSHA384)
	{
		return this->hmaccat->getDigest(HASH_SHA384);
	} else if (x == KEY_HASH_HMACSHA512)
	{
		return this->hmaccat->getDigest(HASH_SHA512);
	} else if (x == KEY_HASH_GMAC)
	{
		return this->gmaccat->getDigest();
	} else if (x == KEY_HASH_POLY1305)
	{
		return this->polycat->getDigest();
	}


	return nullptr;
}