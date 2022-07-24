/*
1. snapshot of all processes 
2. serach for the target process and get its id
3. get a handle to that process 
4. allocate memory for it in the 
5. write the dll to the target process 
6. create a thread for it 


*/

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>


DWORD GetProcessId(const char* procName) {

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return(-1);
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32First(hProcessSnap, &pe32)) {

		do {
			//search for the Process --> _strmpi is used to compare without bothering case sensitivity 
			if (!_strcmpi(pe32.szExeFile, procName)) {

				CloseHandle(hProcessSnap);
				return pe32.th32ProcessID;

			}

		} while (Process32Next(hProcessSnap, &pe32));
	}
}



int main()
{
	
	const char* dllPath = "C:\\simpleDLL.dll";

	DWORD ProcID = GetProcessId("notepad.exe");
	// printf("ProcID: %d", ProcID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcID);

	if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
		LPVOID loc = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (loc) {
		WriteProcessMemory(hProcess, loc, dllPath, strlen(dllPath)+1, NULL);
			
		HMODULE kernel32Handle = GetModuleHandleA("kernel32");
		FARPROC loadLibraryHandle = GetProcAddress(kernel32Handle, "LoadLibraryA");

		HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)loadLibraryHandle, loc, 0, 0);
		std::cout << hThread;
		if (hThread) {
			CloseHandle(hThread);
		}

		}

	}
	if (hProcess) {
		CloseHandle(hProcess);
	}

}

