#include <iostream>
#include <Windows.h>

char saved_buffer[5];
FARPROC messageBoxAddressInline = NULL;
DWORD_PTR messageBoxAddressIAT = NULL;
PIMAGE_THUNK_DATA messageBoxThunk;

int IATHookedMessageBox() {
	int returnValue = MessageBoxW(NULL, L"hooked", L"hooked", 0);
	int choice = MessageBoxW(NULL, L"unhook or not?", L"unhook?", MB_YESNO);
	if (choice == IDYES) {
		DWORD oldProtect;
		DWORD trash;
		VirtualProtect((LPVOID)(&messageBoxThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
		messageBoxThunk->u1.Function = messageBoxAddressIAT;
		VirtualProtect((LPVOID)(&messageBoxThunk->u1.Function), 8, oldProtect, &trash);
	}
	return returnValue;
}

void IAT_hook() {
	// GetModuleHandleA(NULL) returns the CURRENT exe base address, since I inject the DLL into a process
	// it would return that process' base address, and would be the ImageBase 
	LPVOID imageBase = GetModuleHandleA(NULL);

	// Parsing the process' DOSheader and DOSstub to find e_lfanew and get to the NTheaders (finding RVA using imageBase)
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

	// IMAGE_DIRECTORY_ENTRY_IMPORT = 1 --> The import directory's index (amongst all directories)
	// Basically getting poiner to the _IMAGE_DATA_DIRECTORY struct
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// Getting a pointer to the _IMAGE_IMPORT_DESCRIPTOR struct array for the process' imports
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);

	PIMAGE_IMPORT_BY_NAME functionName = NULL;

	// Last importDescriptor member would be zeroed out hence if name is null the array ends
	while (importDescriptor->Name != NULL) {
		// ILT to find function ASCII strings
		PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
		// IAT to find and change function addresses in memory
		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

		// Last originalFirstThunk member would be zeroed out hence if AddressOfData is null the array ends
		while (originalFirstThunk->u1.AddressOfData != NULL) {
			// RVA to PIMAGE_IMPORT_BY_NAME struct of the function that holds Name which is an ASCII string of the func name
			functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);

			if (strcmp(functionName->Name, "MessageBoxA") == 0) {
				// oldProtect --> old virtualProtect permissions to change back later
				DWORD oldProtect;
				DWORD trash;

				// Making the thunk of 'MessageBoxW' have read/write attributes to write over it
				VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);

				messageBoxAddressIAT = firstThunk->u1.Function;
				messageBoxThunk = firstThunk;

				// Rewriting 'MessageBoxW' thunk by changing its value to hookedMessageBox address --> hooking it
				firstThunk->u1.Function = (DWORD_PTR)IATHookedMessageBox;
				VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, oldProtect, &trash);
			}
			// Next member of each array
			++originalFirstThunk;
			++firstThunk;
		}
		// Next DLL
		importDescriptor++;
	}
}

int InlineHookedMessageBox() {
	int returnValue = MessageBoxW(NULL, L"hooked", L"hooked", 0);
	int choice = MessageBoxW(NULL, L"unhook or not?", L"unhook?", MB_YESNO);
	if (choice == IDYES) {
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddressInline, saved_buffer, 5, NULL);
	}
	return returnValue;
}

void API_hook() {
	// Finding address of MessageBoxA within user32.dll
	messageBoxAddressInline = GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");

	// Reading the first 5 bytes for unhooking later
	ReadProcessMemory(GetCurrentProcess(), messageBoxAddressInline, saved_buffer, 5, NULL);

	// Finding delta of our function's address and the actual function's address
	VOID* hookedMessageBoxAddress = &InlineHookedMessageBox;
	DWORD src = (DWORD)messageBoxAddressInline + 5;
	DWORD dst = (DWORD)hookedMessageBoxAddress;
	DWORD* delta = (DWORD*)(dst - src);

	CHAR patch[5] = { 0 };
	memcpy(patch, "\xE9", 1); //JMP instruction
	memcpy(patch + 1, &delta, 4); // Delta of hookedMessageBoxAddress and messageBoxAddressInline in memory
	// Simplified together it's --> JMP &hookedMessageBox

	//writing the JMP + address instruction to the first 5 bytes
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddressInline, patch, 5, NULL);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  nReason, LPVOID lpReserved) {
	switch (nReason) {
	case DLL_PROCESS_ATTACH:
	{
		int hookingType = MessageBoxW(NULL, L"DLL injected and started running\n"
			"Would you like to use the IAT hooking function?", L"DLL Injected", MB_YESNO);

		if (hookingType == IDYES) {
			IAT_hook();
		}
		else if (hookingType == IDNO) {
			hookingType = MessageBoxW(NULL, L"Sooooo, API hooking?", L"say yes :(", MB_YESNO);
			if (hookingType == IDYES) {
				API_hook();
			}
			else {
				MessageBoxW(NULL, L"Fuck you", L"I'm angy >:(", 0);
				ExitProcess(0);
			}

		}
		else {
			MessageBoxW(NULL, L"Fuck you", L"I'm angy >:(", 0);
			ExitProcess(0);
		}
	}
	break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}