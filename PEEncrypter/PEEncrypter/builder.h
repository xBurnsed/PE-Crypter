#pragma once

#include <iostream>
#include <fstream>
#include "rc4Algorithm.h"
#include "Windows.h"

using namespace std;

int builder() {
	ifstream inputCalculator;
	inputCalculator.open("C:\\Users\\uli_6\\Desktop\\calc.exe", ios::in | ios::binary | ios::ate);

	ofstream outputCalc;
	outputCalculator.open("C:\\Users\\uli_6\\Desktop\\encryptedCalc.exe", ios::out | ios::binary);

	if (inputCalculator.is_open() && outputCalculator.is_open()) {
		int calcFileSize = (int)inputCalculator.tellg();
		inputCalculator.seekg(0, ios::beg);

		cout << "Original size of calc.exe: " << calcFileSize << endl;

		// allocate memory:
		char* buffer = new char[calcFileSize]();
		char* cryptedData = new char[calcFileSize]();
		// read data
		inputCalculator.read(buffer, calcFileSize);
		const char* key = "Cervantes";
		rc4Algorithm rc4;
		rc4.crypt(buffer, key, strlen(key), calcFileSize, cryptedData);

		DWORD charSize;
		CryptBinaryToStringA((BYTE*)cryptedData, calcFileSize, CRYPT_STRING_BASE64, NULL, &charSize);

		cout << "number of needed chars: " << charSize << endl;

		char* b64buffer = new char[charSize]();
		CryptBinaryToStringA((BYTE*)cryptedData, calcFileSize, CRYPT_STRING_BASE64, b64buffer, &charSize);
		outputCalculator.write(b64buffer, charSize);

		delete[] b64buffer;
		delete[] buffer;
		delete[] cryptedData;
		inputCalculator.close();
		outputCalculator.close();
	} else {
		cerr << "Unable to open the executable" << endl;
		return -1;
	}

	inputCalculator.open("C:\\Users\\uli_6\\Desktop\\encryptedCalc.exe", ios::in | ios::binary);
	outputCalculator.open("C:\\Users\\uli_6\\Desktop\\decryptedCalc.exe", ios::out | ios::binary);

	if (inputCalculator.is_open() && outputCalculator.is_open()) {
		inputCalculator.seekg(0, inputCalculator.end);
		int calcFileSize = (int)inputCalculator.tellg();
		inputCalculator.seekg(inputCalculator.beg);

		cout << "Original size of encryptedCalc.exe: " << calcFileSize << endl;

		// allocate memory:
		char* buffer = new char[calcFileSize]();

		// read data
		inputCalculator.read(buffer, calcFileSize);

		//decode b64
		DWORD decodedSize;
		CryptStringToBinaryA(buffer, calcFileSize, CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL);
		char* decodedBuffer = new char[decodedSize]();
		CryptStringToBinaryA(buffer, calcFileSize, CRYPT_STRING_BASE64, (BYTE*)decodedBuffer, &decodedSize, NULL, NULL);

		const char* key = "Cervantes";
		rc4Algorithm rc4;
		char* decryptedData = new char[decodedSize]();
		rc4.crypt(decodedBuffer, key, strlen(key), decodedSize, decryptedData);

		outputCalculator.write(decryptedData, decodedSize);

		delete[] decodedBuffer;
		delete[] buffer;
		delete[] decryptedData;
		inputCalculator.close();
		outputCalculator.close();
	} else {
		cerr << "Unable to open the calculator!" << endl;
		return -1;
	}
	return 0;
}