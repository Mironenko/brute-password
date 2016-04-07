#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>

class OpensslException : public std::runtime_error {
public:
	using runtime_error::runtime_error;
};

class BadDecryption : public OpensslException {
public:
	using OpensslException::OpensslException;
};

class Base {
public:
	virtual ~Base() {};
};

template<uint32_t len>
class KeyGenerator : public Base {
public:
	static constexpr uint32_t length = len;
	virtual array<uint8_t, length> genKey(const vector<uint8_t>& password) const = 0;
	~KeyGenerator() {}
};

template<uint32_t len>
class Digest : public Base {
public:
	static constexpr uint32_t length = len;
	virtual array<uint8_t, length> digest(const vector<uint8_t>& data) const = 0;
};

class Sha256 : public Digest<SHA256_DIGEST_LENGTH>{
public:
	array<uint8_t, length> digest(const vector<uint8_t>& data) const {
		array<uint8_t, Digest::length> result;
		SHA256_CTX ctx;
		if (!SHA256_Init(&ctx))
			throw OpensslException("sha256");
		if (!SHA256_Update(&ctx, data.data(), data.size()))
			throw OpensslException("sha256");
		if (!SHA256_Final(result.data(), &ctx))
			throw OpensslException("sha256");
		return result;
	}
};

class Md5 : public Digest<MD5_DIGEST_LENGTH>{
public:
	array<uint8_t, length> digest(const vector<uint8_t>& data) const {
		array<uint8_t, Digest::length> result;
		MD5_CTX ctx;
		if (!MD5_Init(&ctx))
			throw OpensslException("md5");
		if (!MD5_Update(&ctx, data.data(), data.size()))
			throw OpensslException("md5");
		if (!MD5_Final(result.data(), &ctx))
			throw OpensslException("md5");
		return result;
	}
};

template<typename Dgst>
class DigestKeyGenerator : public KeyGenerator<Dgst::length>{
	Dgst mDigest;
public:
	DigestKeyGenerator(const Dgst& dgst) : mDigest(dgst) {};
	array<uint8_t, Dgst::length> genKey(const vector<uint8_t>& password) const {
		return mDigest.digest(password);
	}
};

template<uint32_t blockLen, uint32_t keyLen>
class BlockCipher { //: public Base {
public:
	static constexpr uint32_t blockSize = blockLen;
	static constexpr uint32_t keySize = keyLen;
	// virtual vector<uint8_t> encrypt(const vector<uint8_t>& pt, const array<uint8_t, blockSize>& iv,
	//                              const array<uint8_t, keySize>& key) = 0;
	// virtual vector<uint8_t> decrypt(const vector<uint8_t>& ct, const array<uint8_t, blockSize>& iv,
	//                              const array<uint8_t, keySize>& key) = 0;
};

class Des2KeyEde : public BlockCipher<DES_CBLOCK_LEN, DES_KEY_SZ*2>{

public:
	vector<uint8_t> encrypt(const vector<uint8_t>& pt, const array<uint8_t, blockSize>& iv,
	                        const array<uint8_t, keySize>& key) const {
		// TODO
		throw std::runtime_error("Not implemented yet");
	}

	vector<uint8_t> decrypt(const vector<uint8_t>& ct, const array<uint8_t, blockSize>& iv,
	                        const array<uint8_t, keySize>& key) const {
		DES_cblock k1, k2;
		std::copy(key.begin(), key.begin() + sizeof(k1), k1);
		std::copy(key.begin() + sizeof(k1), key.end(), k2);

		DES_key_schedule ks1, ks2;
		DES_set_key_unchecked(&k1, &ks1);
		DES_set_key_unchecked(&k2, &ks2);

		DES_cblock ivec;
		std::copy(iv.begin(), iv.begin() + sizeof(ivec), ivec);

		std::vector<uint8_t> out(ct.size());
		DES_ede2_cbc_encrypt(ct.data(), out.data(), out.size(),
		                     &ks1, &ks2, &ivec, DES_DECRYPT);

		if (out.back() > 8)
			throw BadDecryption("Invalid padding");

		out.resize(out.size() - out.back());

		return out;
	}
};

class PasswordBasedDecryptor : public Base {
public:
	virtual vector<uint8_t> decrypt(const vector<uint8_t>& password) const = 0;
};

template<typename Cipher>
class PasswordBasedDecryptorImpl : public PasswordBasedDecryptor {
	Cipher mCipher;
	shared_ptr<KeyGenerator<Cipher::keySize> > mKeyGenerator;
	vector<uint8_t> mCt;
	array<uint8_t, Cipher::blockSize> mIv;
public:
	PasswordBasedDecryptorImpl(const Cipher& cipher,
	                           const shared_ptr<KeyGenerator<Cipher::keySize> >& keyGenerator,
	                           const vector<uint8_t>& ct,
	                           const array<uint8_t, Cipher::blockSize>& iv)
		: mCipher(cipher), mKeyGenerator(keyGenerator), mCt(ct), mIv(iv) { }

	vector<uint8_t> decrypt(const vector<uint8_t>& password) const {
		auto key = mKeyGenerator->genKey(password);

		return mCipher.decrypt(mCt, mIv, key);
	};
};


class PasswordVerifier : public Base {
public:
	virtual bool verify(const vector<uint8_t>& password) = 0;
};

template<typename Dgst>
class DigestBasedVerifier : public PasswordVerifier {
	const array<uint8_t, Dgst::length> mOriginalDigest;
	const Dgst mDigester;
	const shared_ptr<PasswordBasedDecryptor> mDecryptor;
public:
	template<typename T>
	DigestBasedVerifier(const T& originalDigest, const shared_ptr<PasswordBasedDecryptor>& decryptor, const Dgst& dgst)
		: mOriginalDigest(originalDigest), mDecryptor(decryptor), mDigester(dgst) {}
	bool verify(const vector<uint8_t>& password) {
		try {
			auto pt = mDecryptor->decrypt(password);
			return mOriginalDigest == mDigester.digest(pt);
		} catch (const BadDecryption& e) {
			return false;
		}
	}
};