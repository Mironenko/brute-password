#include <iostream>
#include <fstream>

#include <algorithm>
#include <array>
#include <vector>
#include <exception>
#include <iomanip>
#include <thread>
#include <condition_variable>
#include <sstream>

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

using DesBlockArray = std::array<uint8_t, Des2KeyEde::blockSize>;
using Sha256Array = std::array<uint8_t, Sha256::length>;
using BruteInputStruct = tuple<DesBlockArray, vector<uint8_t>, Sha256Array>;

BruteInputStruct splitEncryptedData(const vector<uint8_t>& file) {
	DesBlockArray iv;
	std::copy(file.begin(), file.begin() + tuple_size<DesBlockArray>::value, iv.begin());
	auto ct = vector<uint8_t>(file.begin() + tuple_size<DesBlockArray>::value,
	                          file.end() - tuple_size<Sha256Array>::value);
	Sha256Array checkSum;
	copy(file.end() - tuple_size<Sha256Array>::value, file.end(), checkSum.begin());

	return make_tuple(iv, ct, checkSum);
}

uint32_t strToInt(string s) {
	stringstream ss;
	ss << s;
	uint32_t result;
	ss >> result;
	return result;
}

class ThreadWorker : public Base {
	atomic<bool> mStop;
	thread mThread;
protected:
	shared_ptr<mutex> mLock;
	shared_ptr<condition_variable> mCondition;

	virtual void doRun() = 0;

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
			for (size_t i = mStartAlphabetIndex; i != mStopAlphabetIndex; ++i)
			{
				auto c = mAlphabet[i];
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
		auto perThreadRange = alphabet.size() / threadNum;
		for (uint32_t i = 0; i < threadNum; ++i)
		{
			auto startIndex = i * perThreadRange;
			auto stopIndex = (i != threadNum - 1) ? (i + 1) * perThreadRange : alphabet.size();
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
	if (argc < 4)
	{
		cout << "Usage: " << argv[0] << " file minPasswdLen maxPasswdLen [alphabet]\n";
		exit(-1);
	}

	try {
		using Decryptor = PasswordBasedDecryptorImpl<Des2KeyEde>;

		auto file = readFile(argv[1]);
		auto minPasswdLen = strToInt(argv[2]);
		auto maxPasswdLen = strToInt(argv[3]);

		string alphabetStr = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		if (argc == 5)
			alphabetStr = argv[4];
		vector<uint8_t> alphabet(alphabetStr.begin(), alphabetStr.end());

		auto bruteInput = splitEncryptedData(file);
		auto ct = get<1>(bruteInput);
		auto iv = get<0>(bruteInput);
		auto checkSum = get<2>(bruteInput);

		auto keyGenerator = std::make_shared<DigestKeyGenerator<Md5> >(Md5());
		Des2KeyEde algo;

		auto decryptor = make_shared<Decryptor>(algo, keyGenerator, ct, iv);
		Sha256 hashAlgo;
		auto verifier = make_shared<DigestBasedVerifier<Sha256> >(checkSum, decryptor, hashAlgo);

		auto pwd = runBrute(verifier, alphabet, minPasswdLen, maxPasswdLen);
		cout << string(pwd.begin(), pwd.end());
	} catch (const std::exception& e) {
		cout << e.what() << '\n';
		return -1;
	}

	return 0;
}