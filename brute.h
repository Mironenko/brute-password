#ifndef BRUTE_BRUTE_H
#define BRUTE_BRUTE_H

#include <algorithm>
#include <array>
#include <condition_variable>
#include <exception>
#include <string>
#include <thread>
#include <vector>

#include "crypto.h"

using namespace std;

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
		if (prefix.size() >= mMinLen && mVerifier->verify(prefix))
		{
			throw Result(prefix);
		}

		vector<uint8_t> password(prefix.size() + 1);
		std::copy(prefix.begin(), prefix.end(), password.begin());
		for (uint8_t c : mAlphabet)
		{
			password[prefix.size()] = c;
#ifdef DEBUG
			{
				unique_lock<mutex> lock(*mLock);
				cout << string(password.begin(), password.end()) << '\n';
			}
#endif      // DEBUG
			if (password.size() >= mMinLen && mVerifier->verify(password))
			{
				throw Result(password);
			}
			if (password.size() < mMaxLen)
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

#endif // BRUTE_BRUTE_H