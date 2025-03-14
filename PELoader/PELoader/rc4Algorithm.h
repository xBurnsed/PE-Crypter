#pragma once

class rc4Algorithm {
	private:
		unsigned char sBox[256] = {};
		void swap(unsigned int i, unsigned int j);
		void KSA(const char* key, int keySize);
		void PRGA(char* stream, char* ciperOutput, unsigned int dataLen);

	public:
		rc4Algorithm();
		~rc4Algorithm();
		void crypt(char* data, const char* key, int sizeKey, int dataLen, char* cypherOutput);
		char* crypt(char* data, const char* key, int sizeKey, int dataLen);
};

