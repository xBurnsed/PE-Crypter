#include <Windows.h>
#include <iostream>



struct CertData {
	DWORD currentOffset;
	DWORD certLocation;
	DWORD certSize;
};

DWORD bytesRead;

CertData* GetCertData(HANDLE fileHandle, DWORD fileSize) {
	
	CertData* _certData = new CertData();

	char* buffer = new char[fileSize]();

	if (!ReadFile(fileHandle, buffer, fileSize, &bytesRead, NULL))
		std::cout << "Error reading the input file" << std::endl;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS ntHeader;

	if (dosHeader != NULL && dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
		ntHeader = (PIMAGE_NT_HEADERS)((DWORD)buffer + dosHeader->e_lfanew);

		if (!(ntHeader && ntHeader->Signature == IMAGE_NT_SIGNATURE)) {
			std::cout << "Is not a valid PE32 file" << std::endl;
			return NULL;
		}

	}
	else {
		std::cout << "Is not a valid PE32 file" << std::endl;
		return NULL;
	}

	//128 EXTRA BYTES ARE THE ONES NEEDED TO GO FROM THE START OF THE OPTIONAL HEADER TO THE IMAGE_DIRECTORY_ENTRY_SECURITY STRUCT.
	//FOR MORE INFO CHECK IT YOURSELF USING A PE EXPLORER LIKE CFF EXPLORER FOR A 32 BIT EXECUTABLE.

	_certData->currentOffset = dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 128;
	_certData->certLocation = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	_certData->certSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

	return _certData;
}


int main(int argc, char* argv[]) {

	if (argc != 4) {
		std::cout << "\nWrong number of arguments.\nUsage: ./SignatureClone.exe SigFileToClone.exe Target.exe NewFileWithClonedSig.exe" << std::endl;
		std::cout << "E.g. ./SignatureClone.exe Postman.exe MyProgram.exe MyProgramSigned.exe\n\n";
	}

	const char* inputFileName = argv[1];
	const char* targetFileName = argv[2];
	const char* outputFileName = argv[3];

	HANDLE peFile;
	if ((peFile = CreateFileA(inputFileName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		std::cout << "\nCouldn't open the "<< inputFileName << " file.\nMake sure it exists in the same folder as the SignatureClone.exe file.\n\n" << std::endl;
	}

	DWORD fileSize = GetFileSize(peFile, NULL);
	CertData* inputCertData = GetCertData(peFile, fileSize);

	SetFilePointer(peFile, inputCertData->certLocation, NULL, FILE_BEGIN);

	char* certificate = new char[inputCertData->certSize]();


	if (!ReadFile(peFile, certificate, inputCertData->certSize, &bytesRead, NULL))
		std::cout << "\nError reading the cert of the file" << std::endl;


	CloseHandle(peFile);
	//SIGNATURE COPIED INTO certificate BUFFER.

	
	//COPYING TARGET.EXE CONTENT TO DESTINATION.EXE SO WE DON'T OVERWRITE ORIGINAL FILE.
	if (CopyFileA(targetFileName, outputFileName, false) == 0) {
		std::cout << "\nError copying target " << targetFileName << " file content to destionation " << outputFileName << " file.\n";
		std::cout << "Make sure it exists in the same folder as the SignatureClone.exe file.\n\n" << std::endl;
	}


	if ((peFile = CreateFileA(outputFileName, GENERIC_READ | GENERIC_WRITE | FILE_APPEND_DATA, NULL, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		std::cout << "\nCouldn't get a handle for the destination " << outputFileName << " file.\n\n" << std::endl;
	}


	fileSize = GetFileSize(peFile, NULL);
	CertData* targetCertData = GetCertData(peFile, fileSize);

	DWORD pFile;

	if ((pFile = SetFilePointer(peFile, 0, NULL, FILE_END)) == INVALID_SET_FILE_POINTER) {
		std::cout << "\nError changing the file pointer" << std::endl;
	}

	//cert
	if (!WriteFile(peFile, (PBYTE)certificate, inputCertData->certSize, &bytesRead, NULL))
		std::cout << "\nError writing the cert of the file" << std::endl;


	if (SetFilePointer(peFile, targetCertData->currentOffset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		std::cout << "\nError changing the file pointer" << std::endl;
	}

	//rva
	if (!WriteFile(peFile, &pFile, sizeof(DWORD), &bytesRead, NULL))
		std::cout << "\nError writing the RVA of the cert in the new exe" << std::endl;

	if (!WriteFile(peFile, &inputCertData->certSize, sizeof(DWORD), &bytesRead, NULL))
		std::cout << "\nError writing the cert of the file" << std::endl;

	CloseHandle(peFile);
	
	return 0;

}