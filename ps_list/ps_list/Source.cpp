#include <windows.h>
#include<stdio.h>
#include<tchar.h>
#include<Psapi.h>

void PrintProcessesList(DWORD ProcessID) {

	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	// get a handle to process

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		ProcessID);

	if (NULL != hProcess) {
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
			GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	// print process namea and id
	_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, ProcessID);

	//close handle to the process 
	
	CloseHandle(hProcess);
}


int main() {
	DWORD aProcesses[2048], cbNeeded, cProcesses;
	unsigned int i;
	
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
		return 1;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; i++) {
		if (aProcesses[i]) {
			PrintProcessesList(aProcesses[i]);
		}
	
	}
	return 0;
}