#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <algorithm>
#include <array>
#include <vector>
#include <exception>
#include <iomanip>

#define DES_CBLOCK_LEN 8
using namespace std;
class OpensslException : public std::runtime_error {
public:
	using runtime_error::runtime_error;
};

class BadDecryption : public OpensslException {
public:
	using OpensslException::OpensslException;
};

vector<uint8_t> readFile(const string& fileName) {
	std::vector<uint8_t> result;
	std::vector<uint8_t> buffer(1024);
	ifstream f(fileName, ios_base::in | ios_base::binary);
	char* bufferStart = reinterpret_cast<char*>(buffer.data()); 
	for(f.read(bufferStart, buffer.size()); f.gcount() > 0; f.read(bufferStart, buffer.size()))
		std::copy(buffer.begin(), buffer.begin() + f.gcount(), back_inserter(result));

	return result;
}

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

class Sha256 : public Digest<SHA256_DIGEST_LENGTH> {
public:
	array<uint8_t, length> digest(const vector<uint8_t>& data) const {
		array<uint8_t, Digest::length> result;
		SHA256_CTX ctx;
		if(!SHA256_Init(&ctx))
			throw OpensslException("sha256");
		if(!SHA256_Update(&ctx, data.data(), data.size()))
			throw OpensslException("sha256");
		if(!SHA256_Final(result.data(), &ctx))
			throw OpensslException("sha256");
		return result;
	}
};

class Md5 : public Digest<MD5_DIGEST_LENGTH> {
public:
	array<uint8_t, length> digest(const vector<uint8_t>& data) const {
		array<uint8_t, Digest::length> result;
		MD5_CTX ctx;
		if(!MD5_Init(&ctx))
			throw OpensslException("md5");
		if(!MD5_Update(&ctx, data.data(), data.size()))
			throw OpensslException("md5");
		if(!MD5_Final(result.data(), &ctx))
			throw OpensslException("md5");
		return result;
	}
};

template<typename Dgst>
class DigestKeyGenerator : public KeyGenerator<Dgst::length> {
	Dgst digest;
public:
	virtual array<uint8_t, Dgst::length> genKey(const vector<uint8_t>& password) const {
		return digest.digest(password);
	}
};

class PasswordBasedDecryptor : public Base {
public:
	virtual vector<uint8_t> decrypt(const vector<uint8_t>& password) const = 0;
	~PasswordBasedDecryptor() {}
};

template <typename T>
class DesDecryptor : public PasswordBasedDecryptor {
	vector<uint8_t> mCt;
	vector<uint8_t> mIv;
	T mKeyGenerator;

	vector<uint8_t> decryptDesEde(const vector<uint8_t>& ct, const vector<uint8_t>& iv,
                              const array<uint8_t, DES_KEY_SZ*2>& key) const {
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

		if(out.back() > 8)
			throw BadDecryption("Invalid padding");

		out.resize(out.size() - out.back());

		return out;
	}

public:
	DesDecryptor(const vector<uint8_t>& ct, const vector<uint8_t>& iv, const T& keyGenerator) 
		: mCt(ct), mIv(iv), mKeyGenerator(keyGenerator) {}

	vector<uint8_t> decrypt(const vector<uint8_t>& password) const {
		auto key = mKeyGenerator.genKey(password);

		return decryptDesEde(mCt, mIv, key);
	}
};

class PasswordVerifier : public Base {
public:
	virtual bool verify(const vector<uint8_t>& password) = 0;
};

template<typename Dgst, typename Decryptor>
class DigestBasedVerifier : public PasswordVerifier {
	const array<uint8_t, Dgst::length> mOriginalDigest;
	Dgst mDigester;
	Decryptor mDecryptor;
public:
	template <typename T>
	DigestBasedVerifier(const T& originalDigest, const Decryptor& decryptor, const Dgst& dgst) 
		: mOriginalDigest(originalDigest), mDecryptor(decryptor), mDigester(dgst) {}
	bool verify(const vector<uint8_t>& password) {
		try {
			auto pt = mDecryptor.decrypt(password);
			return mOriginalDigest == mDigester.digest(pt);
		} catch (const BadDecryption& e) {
			return false;
		}
	}
};

template <typename Verifier, size_t maxLen>
class PasswordBruter {
	bool mStop;
	Verifier mVerifier;
	template<>
	void brute<maxLen+1>(const string& prefix, uint8_t start, uint8_t end)
	{
		return;
	}
	template<size_t len>
	void brute(const string& prefix, uint8_t start, uint8_t end) {
		vector<uint8_t> password
		for(uint8_t c = start; c <= end; ++c) {

		}
	}
public:
	PasswordBruter(const Verifier& v, const string& prefix, 
		uint8_t start, uint8_t end, size_t minLength, size_t maxLength) 
		: mStop(true);
	{

	}
	void stop() {
		mStop = true;
	}

	void start() {
		mStop = false;
	}

};


int main(int argc, char* argv[]) {
	// TODO: control args
	auto result = readFile("test.txt");
	string password = "abcde";
	// auto md5 = genMd5Key(vector<uint8_t>(password.begin(), password.end()));

	// for (auto a: md5)
	// 	cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// DES_cblock k1, k2;
	// std::copy(md5.begin(), md5.begin() + sizeof(k1), k1);
	// std::copy(md5.begin() + sizeof(k1), md5.end(), k2);

	// DES_key_schedule ks1, ks2;
	// DES_set_key_unchecked(&k1, &ks1);
	// DES_set_key_unchecked(&k2, &ks2);


	auto enc = readFile("test.bin");
	std::vector<uint8_t> iv(DES_CBLOCK_LEN), out(DES_CBLOCK_LEN);
	std::copy(enc.begin(), enc.begin() + DES_CBLOCK_LEN, iv.begin());

	//std::vector<uint8_t> ct(enc.size() - DES_CBLOCK_LEN);
	//std::copy(enc.begin() + DES_CBLOCK_LEN, enc.end() - SHA256_CBLOCK, ct.begin());

	auto ct = readFile("testmy.bin");
	//auto r = decryptDesEde(ct, iv, md5);
	auto d = DesDecryptor<DigestKeyGenerator<Md5>>(ct, iv, DigestKeyGenerator<Md5>());
	auto r = d.decrypt(std::vector<uint8_t>(password.begin(), password.end()));
	cout << string(r.begin(), r.begin() + result.size()) << endl;

	array<uint8_t, Sha256::length> a = {0};
	DigestBasedVerifier<Sha256, DesDecryptor<DigestKeyGenerator<Md5>>> tmp(a, d);

	auto vpassword = std::vector<uint8_t>(password.begin(), password.end());
	cout << tmp.verify(vpassword);

	// cout << "IV\n";
	// for (auto a: iv)
	// 	cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	cout << "data\n";
	cout << string(result.begin(), result.end());
	for (auto a: result)
		cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// DES_ecb3_encrypt(reinterpret_cast<DES_cblock*>(result.data()),
 //        reinterpret_cast<DES_cblock*>(out.data()), &ks1,
 //        &ks2, &ks1, DES_ENCRYPT);
	// cout << "\n";
	// for (auto a: out)
	// 	cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// cout << "\n";

	// DES_ede3_cbc_encrypt(result.data(),
 //        out.data(), DES_CBLOCK_LEN, &ks1,
 //        &ks2, &ks1, reinterpret_cast<DES_cblock*>(iv.data()),
 //        DES_ENCRYPT);
	// cout << "\n";
	// for (auto a: out)
	// 	cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// DES_cbc_encrypt((result.data()),
 //        out.data(), DES_CBLOCK_LEN, &ks1, reinterpret_cast<DES_cblock*>(iv.data()),
 //        DES_ENCRYPT);
	// cout << "\n";
	// for (auto a: out)
	//  	cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// DES_ecb_encrypt(reinterpret_cast<DES_cblock*>(out.data()),
 //        reinterpret_cast<DES_cblock*>(out.data()), &ks2,
 //        DES_ENCRYPT);

	// DES_ecb_encrypt(reinterpret_cast<DES_cblock*>(out.data()),
 //        reinterpret_cast<DES_cblock*>(out.data()), &ks1,
 //        DES_ENCRYPT);
	// cout << "\n";
	// for (auto a: out)
	// 	cout << hex << std::setfill('0') << std::setw(2) << (int)a;



	// cout << "\n";
	// for (auto a: enc)
	// 	cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	return 0;

}