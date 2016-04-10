#include <algorithm>
#include <array>
#include <exception>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <vector>

#include "brute.h"
#include "crypto.h"
#include "utils.h"

using namespace std;

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
		cout << "Found password: " << string(pwd.begin(), pwd.end()) << '\n';
	} catch (const std::exception& e) {
		cout << e.what() << '\n';
		return -1;
	}

	return 0;
}