#include "apiFillerCalls.h"

LPPOINT JunkGetCursorPos() {
    auto lpPoint = new POINT();
    GetCursorPos(lpPoint);
    return lpPoint;
}

VOID JunkGetMenu() {
    auto hWnd = GetActiveWindow();
    GetMenu(hWnd);
    SoundSentry();

}

VOID JunkIsTextUnicode() {
    const char* lpv = "this is a random text";
    auto lpiResult = new INT();
    IsTextUnicode(lpv, strlen(lpv), lpiResult);
}

VOID JunkHeapFunctions(int size) {
    HANDLE hHeap = GetProcessHeap();
    LPVOID lpMem = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
    if (lpMem != nullptr)
        HeapFree(hHeap, NULL, lpMem);
}

VOID JunkGetParent() {
    auto hWnd = GetActiveWindow();
    LPDWORD processId = new DWORD();

    GetWindowThreadProcessId(hWnd, (LPDWORD)processId);
    GetParent(hWnd);
}

void JunkAtomSTR() {
   ATOM at = FindAtomA("Hello this is a test");
   LPSTR buffer = new char[24];
   UINT getAtom = GetAtomNameA(at, buffer, 24);
}

void JunkNumProcessAndHardwareProfile() {
    DWORD numProcesses = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    LPHW_PROFILE_INFOA lpHwProfileInfo = NULL;
    GetCurrentHwProfileA(lpHwProfileInfo);
    LPWSTR buffer = new WCHAR();
    DWORD size = GetCurrentDirectory(0, NULL);
    GetCurrentDirectory(size, buffer);
}