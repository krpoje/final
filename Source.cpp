
// **************************************************************************************
//					*** ANTI-REVERSE ENINEERING TECHNIQUES ***
// **************************************************************************************
// Program implements most commonly used anti-revering techniques:
//
//		* TlsCallback - checks for presence of debugger before entry point
//		* CheckNtGlobalFlag - debugger presence via NtGlobalFlag 
//		* ErasePEHeaderFromMemory - erases PE hader
//		* CheckProcessDebugFlags - state of the process debug flag
//		* code obfuscation - via inserting junk code
// 
// author: Kristijan Poje
// **************************************************************************************


#include <iostream>
#include <string>
#include <Windows.h>
#include <stdio.h>
#include <VersionHelpers.h>


BOOL _DEBUGGED = FALSE;


// ****************************************************************************************
// The TLS callback is called before the process entry point executes, and is executed
// before the debugger breaks.
// Allowing to perform anti-debugging checks before executable module entry point
// call.
// *****************************************************************************************

inline void ErasePEHeaderFromMemory();
char p[9];

#pragma comment(lib, "ntdll.lib")
#pragma comment(linker, "/include:__tls_used")
#pragma section(".CRT$XLY", long, read)
__declspec(thread) int var = 0xDEADBEEF;
VOID WINAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	var = 0xB15BADB0; // required for TLS Callback call


	if (IsDebuggerPresent())
	{	
		_DEBUGGED = TRUE;
		ErasePEHeaderFromMemory();
	}
	else
	{		
		char secret[9];
		secret[0] = 102;
		secret[1] = 108;
		secret[2] = 97;
		secret[3] = 103;
		secret[4] = 95;
		secret[5] = 102;
		secret[6] = 101;
		secret[7] = 114;
		secret[8] = 0;

		std::cout << "Exiting program..." << std::endl;

		for (int i = 0; i < 9; ++i)
		{	
			p[i] = secret[i];
		}

	}
}
__declspec(allocate(".CRT$XLY"))PIMAGE_TLS_CALLBACK g_tlsCallback = TlsCallback;



// ******************************************************************************************
// NtGlobalFlag - to check if process has been started with debugger check
// the value of the NtGlobalFlag filed in the PEB structure. NtGlobalFlag field is located
// by the 0x068 and 0x0bc for x32 and x64 systems relative to the beginning of the 
// PEB structure.
// *******************************************************************************************

// Current PEB for 64bit and 32bit processes
PVOID GetPEB()
{
#ifdef _WIN64
	return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
	return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}


// Get PEB for WOW64 Process
PVOID GetPEB64()
{
	PVOID pPeb = 0;

#ifndef _WIN64
	// 1. There are two copies of PEB - PEB64 and PEB32 in WOW64 process
	// 2. PEB64 follows after PEB32
	// 3. This is true for versions lower than Windows 8, else __readfsdword returns address of real PEB64

	if (IsWindows8OrGreater())
	{
		BOOL isWow64 = FALSE;
		typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
		pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
			GetProcAddress(GetModuleHandleA("Kernel32.dll"), "IsWow64Process");

		if (fnIsWow64Process(GetCurrentProcess(), &isWow64))
		{
			if (isWow64)
			{
				pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
				pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
			}
		}
	}

#endif
	return pPeb;
}


#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

void CheckNtGlobalFlag()
{
	PVOID pPeb = GetPEB();
	PVOID pPeb64 = GetPEB64();
	DWORD offsetNtGlobalFlag = 0;

#ifdef _WIN64
	offsetNtGlobalFlag = 0xBC;

#else
	offsetNtGlobalFlag = 0x68;

#endif
	DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
	if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
	{
		_DEBUGGED = TRUE;
	}
	if (pPeb64)
	{
		DWORD NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xBC);
		if (NtGlobalFlagWow64 & NT_GLOBAL_FLAG_DEBUGGED)
		{
			_DEBUGGED = TRUE;
		} 
	}
}

// **********************************************************************************************
// Function will erase PE header from memory preventing a successful image
// if dumped.
// **********************************************************************************************

inline void ErasePEHeaderFromMemory()
{
	DWORD OldProtect = 0;

	// base address of module
	char *pBaseAddr = (char*)GetModuleHandle(NULL);

	// change memory protection
	VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
		PAGE_READWRITE, &OldProtect);

	// erase the header
	ZeroMemory(pBaseAddr, 4096);
}


// ***********************************************************************************************
// CheckProcessDebugFlags will return true if the EPROCESS->NoDebugInherit is == FALSE, 
// the reason we check for false is because the NtQueryProcessInformation function returns the
// inverse of EPROCESS->NoDebugInherit 
// ***********************************************************************************************

inline bool CheckProcessDebugFlags()

	typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD NoDebugInherit = 0;
	NTSTATUS Status;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
			"NtQueryInformationProcess");

	Status = NtQIP(GetCurrentProcess(),
		0x1f, // ProcessDebugFlags
		&NoDebugInherit, 4, NULL);

	if (Status != 0x00000000)
		return false;

	if (NoDebugInherit == FALSE)
		return true;
	else
		return false;
}


#define _NEWLINE '\n'
#define JUNK_CODE			\
	__asm { push eax}		\
	__asm {xor eax, eax}    \
	__asm {setpo al}        \
	__asm {push edx}        \
	__asm {xor edx, eax}    \
	__asm {sal edx, 2}      \
	__asm {xchg eax, edx}   \
	__asm {pop edx}         \
	__asm { or eax, ecx}    \
	__asm {pop eax}


// Function takes values of the input parmeters and returns sum.
// Rest of the code is used as a cover up - code obfuscation.
int ad(int n, int p)
{	
	JUNK_CODE
	int rez = 0;
	int m = 15;
	__asm {
		mov eax, n
			mov ebx, p
			add eax, ebx
			mov rez, eax
			; a_dest:
			; mov ebx, m
			; xor ebx, ebx
			; cmp rez, eax
			; jne a_dest

	}
	return rez;
}

// Function returns integer value of 44 - code obfuscation is used here as well.
int basicFunction()
{
	int n, m, j, k, z;
	n = 27775;
	k = 17 * n - 44;
	z = 14 - 78;
	m = 22;
	JUNK_CODE
	__asm {
		mov eax, n
		mov ebx, k
		mov ecx, z
		mov eax, 44
		mov j, eax
		nop
		nop
		nop
	}

	return j;
}

// Returns new line
char f(int *n, int m)
{	
	JUNK_CODE
	return _NEWLINE;
}



// **************************************************************************************
//							    *** MAIN FUNCTION ***
// **************************************************************************************

int main(int argc, char **argv)
{
	TlsCallback(NULL, NULL, NULL);
	CheckNtGlobalFlag();
	*p = NULL;

	int i, j, k, b;

	j = basicFunction();
	k = basicFunction() * ad(j, j);

	for (i = 0, b = k + j - k*j + 2 * 4 * k - j; i < rand() % 100 + 10; ++i)
	{
		if (IsDebuggerPresent()) 
		{
			std::cout << basicFunction() << f(&i, 12);
		}
		else
		{	
			std::cout << "status " << i << f(&i, j);
			std::cout << "Exiting program..." << f(&i, k);
			Sleep(1000);
		}
	} 
	if (IsDebuggerPresent()) 
	{
		*p = NULL;
		MessageBoxA(NULL, "Error", "", MB_OK | MB_ICONERROR);
			
	}
	else { 

		BOOL isDebugged = CheckProcessDebugFlags();


		if (!isDebugged && !_DEBUGGED)
		{
			std::cout << "Exiting program..." << f(&i, k);

	    }

	}


	system("pause");

	return 0;
}

