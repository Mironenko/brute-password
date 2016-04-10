#ifndef BRUTE_UTILS_H
#define BRUTE_UTILS_H

#include <fstream>
#include <sstream>
#include <vector>

using namespace std;

vector<uint8_t> readFile(const string& fileName) {
	std::vector<uint8_t> result;
	std::vector<uint8_t> buffer(1024);
	ifstream f(fileName, ios_base::in | ios_base::binary);
	char* bufferStart = reinterpret_cast<char*>(buffer.data());
	for (f.read(bufferStart, buffer.size()); f.gcount() > 0; f.read(bufferStart, buffer.size()))
		std::copy(buffer.begin(), buffer.begin() + f.gcount(), back_inserter(result));

	return result;
}

uint32_t strToInt(string s) {
	stringstream ss;
	ss << s;
	uint32_t result;
	ss >> result;
	return result;
}

#endif // BRUTE_UTILS_H