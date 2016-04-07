#include <iostream>
#include <fstream>
#include <cstdint>
#include <algorithm>
#include <array>
#include <vector>
#include <exception>
#include <iomanip>
#include <thread>
#include <condition_variable>

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

class ThreadWorker : public Base {
	bool mStop;
	thread mThread;
protected:
	shared_ptr<mutex> mLock;
	shared_ptr<condition_variable> mCondition;

	virtual void doRun() {
		while (!isStop())
			cout << "hello\n";
	}

	virtual void notify() {
		unique_lock<mutex> lock(*mLock);
		mCondition->notify_all();
	}

	void run() {
		{
			unique_lock<mutex> lock(*mLock);
		}
		doRun();
		mStop = true;
		notify();
	}
public:
	ThreadWorker(const shared_ptr<mutex>& lock, shared_ptr<condition_variable>& condition)
		: mStop(false), mLock(lock), mCondition(condition), mThread(&ThreadWorker::run, this)
	{}

	bool isStop() {
		return mStop;
	}

	void stop() {
		mStop = true;

		mThread.join();
	}
};

class PasswordBruter : public ThreadWorker {
	shared_ptr<PasswordVerifier> mVerifier;
	const vector<uint8_t> mAlphabet;
	const size_t mMinLen;
	const size_t mMaxLen;
	const size_t mStartAlphabetIndex;
	const size_t mStopAlphabetIndex;

	atomic<bool> mSucceed;
	vector<uint8_t> mPassword;

	struct Result
	{
		vector<uint8_t> mPassword;
		Result(vector<uint8_t> r) : mPassword(r) {}
	};

	void brute(const vector<uint8_t>& prefix) {
#ifdef DEBUG
		{
			unique_lock<mutex> lock(*mLock);
			cout << string(prefix.begin(), prefix.end()) << '\n';
		}
#endif  // DEBUG

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
			password[prefix.size()] = c;

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
	PasswordBruter(const shared_ptr<mutex>& lock, shared_ptr<condition_variable>& condition,
	               const shared_ptr<PasswordVerifier>& v, const string& prefix,
	               const vector<uint8_t>& alphabet, size_t minLength, size_t maxLength,
	               size_t startIndex, size_t stopIndex)
		: ThreadWorker(lock, condition), mVerifier(v), mAlphabet(alphabet),
		mMinLen(minLength), mMaxLen(maxLength), mSucceed(false),
		mStartAlphabetIndex(startIndex), mStopAlphabetIndex(stopIndex)
	{}

	bool succeed() const {
		return mSucceed;
	}

	const vector<uint8_t>& password() const {
		return mPassword;
	}
};

vector<uint8_t> runBrute(const shared_ptr<PasswordVerifier>& verifier, const vector<uint8_t>& alphabet,
                         size_t minLength, size_t maxLength) {
	const uint32_t threadNum = thread::hardware_concurrency();
	const uint32_t alphabetRange = alphabet.size() / threadNum;


	vector<shared_ptr<PasswordBruter> > bruters;
	auto hasPassword = [](const shared_ptr<PasswordBruter>& p) -> bool {
						   return p->succeed();
					   };
	auto isReady = [](const shared_ptr<PasswordBruter>& p) -> bool {
					   return p->isStop();
				   };
	{
		auto lock = make_shared<mutex>();
		auto condition = make_shared<condition_variable>();
		unique_lock<mutex> l(*lock);

		for (uint32_t i = 0; i < threadNum; ++i)
		{
			auto startIndex = i * threadNum;
			auto stopIndex = (i == threadNum - 1) ? (i + 1) * threadNum : alphabet.size();
			auto bruter = make_shared<PasswordBruter>(lock, condition, verifier, "", alphabet,
			                                          minLength, maxLength, startIndex, stopIndex);
			bruters.push_back(bruter);
		}

		while (count_if(bruters.begin(), bruters.end(), hasPassword) == 0 &&
		       count_if(bruters.begin(), bruters.end(), isReady) != bruters.size())
		{
			condition->wait(l);
		}
	}

	for (auto& bruter: bruters)
	{
		bruter->stop();
	}

	auto luckyBruter = find_if(bruters.begin(), bruters.end(), hasPassword);
	if (luckyBruter != bruters.end())
		return (*luckyBruter)->password();

	throw runtime_error("Password not found");
}

int main(int argc, char* argv[]) {
	// TODO: control args
	auto result = readFile("test.txt");
	string password = "abcde";
	vector<uint8_t> pass(password.begin(), password.end());
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
	//std::array<uint8_t, DES_CBLOCK_LEN> iv;//, out(DES_CBLOCK_LEN);
	//std::copy(enc.begin(), enc.begin() + DES_CBLOCK_LEN, iv.begin());

	//std::vector<uint8_t> ct(enc.size() - DES_CBLOCK_LEN);
	//std::copy(enc.begin() + DES_CBLOCK_LEN, enc.end() - SHA256_CBLOCK, ct.begin());

	auto ct = readFile("testmy.bin");
	std::array<uint8_t, DES_CBLOCK_LEN> iv;//, out(DES_CBLOCK_LEN);
	std::copy(enc.begin(), enc.begin() + DES_CBLOCK_LEN, iv.begin());
	//auto r = decryptDesEde(ct, iv, md5);
	PasswordBasedDecryptorImpl<Des2KeyEde> p(Des2KeyEde(), std::make_shared<DigestKeyGenerator<Md5> >(Md5()), ct, iv);
	auto r = p.decrypt(pass);
	cout << string(r.begin(), r.begin() + result.size()) << endl;
	auto dgst = Sha256().digest(r);
	cout << hex << (int)dgst[0];
	//return 0;
	auto d = make_shared<PasswordBasedDecryptorImpl<Des2KeyEde> >(Des2KeyEde(),
	                                                              std::make_shared<DigestKeyGenerator<Md5> >(Md5()), ct, iv);

	//auto r = d.decrypt(std::vector<uint8_t>(password.begin(), password.end()));
	//cout << string(r.begin(), r.begin() + result.size()) << endl;

	// ThreadWorker t;
	// t.start();
	// std::this_thread::sleep_for(std::chrono::milliseconds(10));
	// t.stop();

	//vector<uint8_t> alphabet = {'a', 'b', 'c'};

	array<uint8_t, Sha256::length> a = {0x9d, 0x79, 0x25, 0xbf, 0x63, 0x64, 0x31, 0xf6, 0xca, 0x2b, 0x46, 0xf9, 0xba, 0xd3, 0x3d, 0x67, 0x4d, 0x90, 0x03, 0xc6, 0xec, 0xf6, 0x8e, 0x82, 0xc8, 0x46, 0xec, 0x08, 0x07, 0xe0, 0x49, 0xea};


	auto tmp = make_shared<DigestBasedVerifier<Sha256> >(a, d, Sha256());
	// PasswordBruter p(tmp, "", alphabet, 0, 3);
	// p.start();
	cout << tmp->verify(pass);
	//return 0;


	vector<uint8_t> alphabet1 = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', };

	//array<uint8_t, Sha256::length> b = {0};
	auto tmp1 = make_shared<DigestBasedVerifier<Sha256> >(a, d, Sha256());

	try {
		auto pwd = runBrute(tmp1, alphabet1, 0, 5);
		cout << string(pwd.begin(), pwd.end());
	} catch (const runtime_error& e) {
		cout << e.what();
	}
	return 0;





	// PasswordBruter p1(tmp1, "", alphabet1, 0, 10);
	// p1.start();
	// std::this_thread::sleep_for(std::chrono::milliseconds(10));
	// p.stop();
	// p1.stop();
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