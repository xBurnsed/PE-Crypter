#pragma once

#include <iostream>
#include <fstream>
#include "rc4Algorithm.h"
#include "Windows.h"

using namespace std;

//TODO: AES && XOR options

int builder() {

	ifstream calcExe;
	calcExe.open("C:\\Users\\uli_6\\Desktop\\calc.exe", ios::in | ios::binary | ios::ate);

	ofstream encryptedCalc;
	encryptedCalc.open("C:\\Users\\uli_6\\Desktop\\encryptedCalc.exe", ios::out | ios::binary);

	if (calcExe.is_open() && encryptedCalc.is_open()) {
		int calcFileSize = (int)calcExe.tellg();
		calcExe.seekg(0, ios::beg);

		cout << "Tamaño en bytes de la calculadora original: " << calcFileSize << endl;

		// allocate memory:
		char* buffer = new char[calcFileSize]();
		char* cryptedData = new char[calcFileSize]();

		// read data
		calcExe.read(buffer, calcFileSize);

		const char* key = "Cervantes";

		rc4Algorithm rc4;

		rc4.crypt(buffer, key, strlen(key), calcFileSize, cryptedData);

		DWORD charSize;

		CryptBinaryToStringA((BYTE*)cryptedData, calcFileSize, CRYPT_STRING_BASE64, NULL, &charSize);

		cout << "number of needed chars: " << charSize << endl;


		char* b64buffer = new char[charSize]();

		CryptBinaryToStringA((BYTE*)cryptedData, calcFileSize, CRYPT_STRING_BASE64, b64buffer, &charSize);


		encryptedCalc.write(b64buffer, charSize);

		delete[] b64buffer;
		delete[] buffer;
		delete[] cryptedData;
		calcExe.close();
		encryptedCalc.close();
	}
	else {
		cerr << "No se ha podido abrir el ejecutable!" << endl;
		return -1;
	}

	calcExe.open("C:\\Users\\uli_6\\Desktop\\encryptedCalc.exe", ios::in | ios::binary);
	encryptedCalc.open("C:\\Users\\uli_6\\Desktop\\decryptedCalc.exe", ios::out | ios::binary);

	if (calcExe.is_open() && encryptedCalc.is_open()) {
		calcExe.seekg(0, calcExe.end);
		int calcFileSize = (int)calcExe.tellg();
		calcExe.seekg(calcExe.beg);

		cout << "Tamaño en bytes de la calculadora original: " << calcFileSize << endl;

		// allocate memory:
		char* buffer = new char[calcFileSize]();

		// read data
		calcExe.read(buffer, calcFileSize);

		//decode b64

		DWORD decodedSize;
		CryptStringToBinaryA(buffer, calcFileSize, CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL);

		char* decodedBuffer = new char[decodedSize]();

		CryptStringToBinaryA(buffer, calcFileSize, CRYPT_STRING_BASE64, (BYTE*)decodedBuffer, &decodedSize, NULL, NULL);

		const char* key = "Cervantes";

		rc4Algorithm rc4;

		char* decryptedData = new char[decodedSize]();

		rc4.crypt(decodedBuffer, key, strlen(key), decodedSize, decryptedData);

		encryptedCalc.write(decryptedData, decodedSize);

		delete[] decodedBuffer;
		delete[] buffer;
		delete[] decryptedData;
		calcExe.close();
		encryptedCalc.close();
	}
	else {
		cerr << "No se ha podido abrir el ejecutable!" << endl;
		return -1;
	}

	return 0;


	//strcpy_s(crypted, strlen(crypted), toEncrypt);	

}