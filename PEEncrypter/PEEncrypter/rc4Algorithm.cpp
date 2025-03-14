#include "rc4Algorithm.h"

rc4Algorithm::rc4Algorithm() {}

rc4Algorithm::~rc4Algorithm() {}


void rc4Algorithm::swap(unsigned int i, unsigned int j) {
	unsigned char temp = sBox[i];
	sBox[i] = sBox[j];
	sBox[j] = temp;
}

void rc4Algorithm::KSA(const char* key, int keySize) {
	for (unsigned int i = 0; i < 256; i++) {
		sBox[i] = i;
	}
	unsigned int j = 0;
	for (unsigned i = 0; i < 256; i++) {
		j = (j + key[i % keySize] + sBox[i]) % 256;
		swap(i, j);
	}
}

void rc4Algorithm::PRGA(char* stream, char* cipherOutput, unsigned int dataLen) {
	int i = 0;
	int j = 0;
	for (unsigned int n = 0; n < dataLen; n++) {
		i = (i + 1) % 256;
		j = (j + sBox[i]) % 256;
		swap(i, j);
		cipherOutput[n] = (sBox[(sBox[i] + sBox[j]) % 256]) ^ stream[n];
	}
}

void rc4Algorithm::crypt(char* data, const char* key, int sizeKey, int dataLen, char* cipherOutput) {
	KSA(key, sizeKey);
	PRGA(data, cipherOutput, dataLen);
}
