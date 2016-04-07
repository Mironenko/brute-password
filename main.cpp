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
#include <thread>
#define DES_CBLOCK_LEN 8
using namespace std;

#include "CryptoStuff.h"

vector<uint8_t> readFile(const string& fileName) {
	std::vector<uint8_t> result;
	std::vector<uint8_t> buffer(1024);
	ifstream f(fileName, ios_base::in | ios_base::binary);
	char* bufferStart = reinterpret_cast<char*>(buffer.data());
	for (f.read(bufferStart, buffer.size()); f.gcount() > 0; f.read(bufferStart, buffer.size()))
		std::copy(buffer.begin(), buffer.begin() + f.gcount(), back_inserter(result));

	return result;
}


class ThreadWorker {
	bool mStop;
	std::unique_ptr<thread> mThread;
protected:
	bool isStop() {
		return mStop;
	}
	virtual void doRun() {
		while (!isStop())
			cout << "hello\n";
	}
	virtual void notify() {
		return;
	}
	void run() {
		doRun();
		notify();
	}
public:
	void stop() {
		mStop = true;

		if (mThread)
			mThread->join();

		mThread.reset();
	}

	void start() {
		mStop = false;
		if (!mThread)
			mThread = make_unique<thread>(&ThreadWorker::run, this);
	}
};

class PasswordBruter : public ThreadWorker {
	shared_ptr<PasswordVerifier> mVerifier;
	const vector<uint8_t> mAlphabet;
	const size_t mMinLen;
	const size_t mMaxLen;
	const size_t mStartAlphabetIndex;
	const size_t mStopAlphabetIndex;

	bool mSucceed;
	vector<uint8_t> mPassword;

	struct Result
	{
		vector<uint8_t> mPassword;
		Result(vector<uint8_t> r) : mPassword(r) {}
	};

	void brute(const vector<uint8_t>& prefix) {
		cout << string(prefix.begin(), prefix.end()) << '\n';

		if (prefix.size() > mMaxLen)
			return;

		if (prefix.size() >= mMinLen && mVerifier->verify(prefix))
		{
			throw Result(prefix);
		}

		vector<uint8_t> password(prefix.size() + 1);
		std::copy(prefix.begin(), prefix.end(), password.begin());
		for (uint8_t c : mAlphabet)
		{
			password[prefix.size() - 1] = c;

			if (password.size() >= mMinLen && mVerifier->verify(password))
			{
				throw Result(password);
			}

			brute(password);
			if (isStop())
				return;
		}
		return;
	}

protected:
	void doRun() {
		try {
			vector<uint8_t> password(1);
			for (uint8_t c : mAlphabet)
			{
				password[0] = c;

				brute(password);
			}
		} catch (const Result& r) {
			mPassword = r.mPassword;
			mSucceed = true;
		}
	}

public:
	PasswordBruter(const shared_ptr<PasswordVerifier>& v, const string& prefix,
	               vector<uint8_t>& alphabet, size_t minLength, size_t maxLength)
		: mVerifier(v), mAlphabet(alphabet),
		mMinLen(minLength), mMaxLen(maxLength), mSucceed(false),
		mStartAlphabetIndex(0), mStopAlphabetIndex(2)
	{

	}


};

// template <typename Verifier, size_t maxLen>
// template<>
// bool PasswordBruter<Verifier, maxLen>::brute<maxLen+1>(const vector<uint8_t>& prefix, uint8_t start, uint8_t end)
// {
//  return false;
// }


int main(int argc, char* argv[]) {
	// TODO: control args
	auto result = readFile("test.txt");
	string password = "abcde";
	// auto md5 = genMd5Key(vector<uint8_t>(password.begin(), password.end()));

	// for (auto a: md5)
	//  cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// DES_cblock k1, k2;
	// std::copy(md5.begin(), md5.begin() + sizeof(k1), k1);
	// std::copy(md5.begin() + sizeof(k1), md5.end(), k2);

	// DES_key_schedule ks1, ks2;
	// DES_set_key_unchecked(&k1, &ks1);
	// DES_set_key_unchecked(&k2, &ks2);


	auto enc = readFile("test.bin");
	std::array<uint8_t, DES_CBLOCK_LEN> iv;//, out(DES_CBLOCK_LEN);
	std::copy(enc.begin(), enc.begin() + DES_CBLOCK_LEN, iv.begin());

	//std::vector<uint8_t> ct(enc.size() - DES_CBLOCK_LEN);
	//std::copy(enc.begin() + DES_CBLOCK_LEN, enc.end() - SHA256_CBLOCK, ct.begin());

	auto ct = readFile("testmy.bin");
	//auto r = decryptDesEde(ct, iv, md5);
	auto d = make_shared<PasswordBasedDecryptorImpl<Des2KeyEde> >(Des2KeyEde(),
	                                                              std::make_shared<DigestKeyGenerator<Md5> >(Md5()), ct, iv);
	//auto r = d.decrypt(std::vector<uint8_t>(password.begin(), password.end()));
	//cout << string(r.begin(), r.begin() + result.size()) << endl;

	ThreadWorker t;
	t.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	t.stop();

	vector<uint8_t> alphabet = {'a', 'b', 'c'};

	array<uint8_t, Sha256::length> a = {0};
	auto tmp = make_shared<DigestBasedVerifier<Sha256> >(a, d, Sha256());
	PasswordBruter p(tmp, "", alphabet, 0, 3);
	p.start();


	vector<uint8_t> alphabet1 = {'d', 'e', 'f'};

	array<uint8_t, Sha256::length> b = {0};
	auto tmp1 = make_shared<DigestBasedVerifier<Sha256> >(b, d, Sha256());
	PasswordBruter p1(tmp1, "", alphabet1, 0, 10);
	p1.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	p.stop();
	p1.stop();
	// //auto digester = Digest<S>

	// DigestBasedVerifier<Sha256, DesDecryptor<DigestKeyGenerator<Md5>>> tmp(a, d, Sha256());

	// auto vpassword = std::vector<uint8_t>(password.begin(), password.end());
	// cout << tmp.verify(vpassword);

	// // cout << "IV\n";
	// // for (auto a: iv)
	// //   cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// cout << "data\n";
	// cout << string(result.begin(), result.end());
	// for (auto a: result)
	//  cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// vector<uint8_t> alphabet = {'a','b','c'};
	// PasswordBruter<decltype(tmp), 3> p(tmp, "", alphabet, 0, 3);
	// p.start();

	// // DES_ecb3_encrypt(reinterpret_cast<DES_cblock*>(result.data()),
	// //        reinterpret_cast<DES_cblock*>(out.data()), &ks1,
	// //        &ks2, &ks1, DES_ENCRYPT);
	// // cout << "\n";
	// // for (auto a: out)
	// //   cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// // cout << "\n";

	// // DES_ede3_cbc_encrypt(result.data(),
	// //        out.data(), DES_CBLOCK_LEN, &ks1,
	// //        &ks2, &ks1, reinterpret_cast<DES_cblock*>(iv.data()),
	// //        DES_ENCRYPT);
	// // cout << "\n";
	// // for (auto a: out)
	// //   cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// // DES_cbc_encrypt((result.data()),
	// //        out.data(), DES_CBLOCK_LEN, &ks1, reinterpret_cast<DES_cblock*>(iv.data()),
	// //        DES_ENCRYPT);
	// // cout << "\n";
	// // for (auto a: out)
	// //   cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	// // DES_ecb_encrypt(reinterpret_cast<DES_cblock*>(out.data()),
	// //        reinterpret_cast<DES_cblock*>(out.data()), &ks2,
	// //        DES_ENCRYPT);

	// // DES_ecb_encrypt(reinterpret_cast<DES_cblock*>(out.data()),
	// //        reinterpret_cast<DES_cblock*>(out.data()), &ks1,
	// //        DES_ENCRYPT);
	// // cout << "\n";
	// // for (auto a: out)
	// //   cout << hex << std::setfill('0') << std::setw(2) << (int)a;



	// // cout << "\n";
	// // for (auto a: enc)
	// //   cout << hex << std::setfill('0') << std::setw(2) << (int)a;

	return 0;

}