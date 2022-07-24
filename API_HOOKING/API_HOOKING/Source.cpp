#include <Windows.h>
#include <iostream>

FARPROC MessageBoxAddress = NULL;
SIZE_T bytesWritten = 0;
char MessageBoxOriginalBytes[6] = {};

int __stdcall HookedMessageBoxA(HWND   hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT   uType) {
	
	std::cout << "Hello From The Hooked Function" << std::endl;
	std::cout << "Text: " << (LPCSTR)lpText << "\n Caption: " << (LPCSTR)lpCaption << std::endl;

	//Unhook the original messageBoxA 
	/*
	BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
	*/

	WriteProcessMemory(GetCurrentProcess(), (LPVOID)MessageBoxAddress, MessageBoxOriginalBytes, sizeof(MessageBoxOriginalBytes), &bytesWritten);

	return MessageBoxA(NULL, lpText, lpCaption, uType);
}

int main() {
	MessageBoxA(NULL, "Hello Before Hooking", "Not Hooked", MB_OK);
	HINSTANCE library = LoadLibraryA("user32.dll");
	SIZE_T bytesRead = 0;
	MessageBoxAddress = GetProcAddress(library, "MessageBoxA"); 

	// Read the original bytes of MessageBoxA
	/*
	BOOL ReadProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPCVOID lpBaseAddress,
  [out] LPVOID  lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesRead
);
*/
	ReadProcessMemory(GetCurrentProcess(), MessageBoxAddress, MessageBoxOriginalBytes, 6, &bytesRead);

	// creating the patch -> push HookedMessageBoxAddress , ret
	void* hookedMessageBoxAddress = &HookedMessageBoxA;
	char patch[6] = { 0 };
	
	/*
	 errno_t memcpy_s(
   void *dest,
   size_t destSize,
   const void *src,
   size_t count
);
	*/

	/*
	1. write the opcode 0x68 of the push instruction
	2. write the destination address
	3. write the opcode 0xC3 of the ret 
	*/

	memcpy_s(patch, 1, "\x68", 1);
	memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4);
	memcpy_s(patch + 5, 1, "\xC3", 1);
	
	//patch MessageBoxA 

	WriteProcessMemory(GetCurrentProcess(), (LPVOID)MessageBoxAddress, patch, sizeof(patch), &bytesWritten);

	//MessageBoxA after hook

	MessageBoxA(NULL, "Hello", "Hello", MB_OK);
	return 0;

}