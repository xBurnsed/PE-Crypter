#pragma once

#include <iostream>
#include <fstream>
#include "rc4Algorithm.h"
#include "Windows.h"
#include "builder.h"

using namespace std;

#pragma comment(lib, "Crypt32.lib")

int OutputDataToFile(char* data, const char* fileNameHeader, DWORD dataSize, const char* key) {
	FILE* hFile;
	if (fopen_s(&hFile, (char*)fileNameHeader, "w+") == 0) {
		
		//Used Encrypt key

		fprintf_s(hFile, "\n\n\tconst char* key = \"");
		for (unsigned int i = 0; i < strlen(key); i++) {
			fprintf_s(hFile, "%c", key[i]);
		}
		fprintf_s(hFile, "\";\n\n\t");
		
		
		//Encrypted data
		fprintf_s(hFile, "unsigned char encData[] = {\n\t");
		
		for (DWORD i = 0; i < dataSize; i++) {
			if (i == dataSize - 1) {
				fprintf_s(hFile, "0x%02X", data[i]);
				fprintf_s(hFile, "\n\t};");
			}
			else {
				fprintf_s(hFile, "0x%02X, ", data[i]);
			}
			if (i+1 % 16 == 0) {
				fprintf_s(hFile, "\n\t");
			}
		}

		fclose(hFile);
		return 0;
	}
	else {
		return -1;
	}

}

void usage(int argc) {
	if (argc != 3) {
		std::cout << "\nWrong number of arguments.\nUsage: ./PEEncrypter.exe target.exe EncryptionKey\n"<<std::endl;
	}
}

//TODO: Change hardcoded input (RC4 key, filenames..) for arguments in console input

int main(int argc, char* argv[]) {

	//UNCOMMENT TO GENERATE ENCRYPTED .EXE AND DECRYPTED .EXE FOR TESTING PURPOSES.
	/*if (builder() == -1) {
		cout << "Builder test failed" << endl;
	}*/

	usage(argc);

	ifstream inExe;
	inExe.open(argv[1], ios::in | ios::binary | ios::ate);

	if (inExe.is_open()) {
		int calcFileSize = (int)inExe.tellg();
		inExe.seekg(0, ios::beg);

		cout << "Tamaño en bytes de la calculadora original: " << calcFileSize << endl;

		// allocate memory:
		char* buffer = new char[calcFileSize]();
		char* cryptedData = new char[calcFileSize]();

		// read data
		inExe.read(buffer, calcFileSize);

		const char* key = argv[2]; 

		rc4Algorithm rc4;

		rc4.crypt(buffer, key, strlen(key), calcFileSize, cryptedData);

		DWORD charSize;

		CryptBinaryToStringA((BYTE*)cryptedData, calcFileSize, CRYPT_STRING_BASE64, NULL, &charSize);

		cout << "number of needed chars: " << charSize << endl;

		char* b64buffer = new char[charSize]();

		CryptBinaryToStringA((BYTE*)cryptedData, calcFileSize, CRYPT_STRING_BASE64, b64buffer, &charSize);


		if (OutputDataToFile(b64buffer, "shellc.h", charSize, key) == 0) {

			cout << "Output has been succesfull!" << endl;

		}
		else {
			cout << "Output has failed!" << endl;
		}

		delete[] buffer;
		delete[] cryptedData;
		delete[] b64buffer;
		inExe.close();
	}
	else {
		cerr << "No se ha podido abrir el ejecutable!" << endl;
		return 0;
	}

}