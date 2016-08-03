#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>

typedef HANDLE(WINAPI* pCreateFile)(
	_In_     LPCTSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
	);
typedef BOOL(WINAPI* pWriteFile)(
	_In_        HANDLE       hFile,
	_In_        LPCVOID      lpBuffer,
	_In_        DWORD        nNumberOfBytesToWrite,
	_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

typedef struct remotecode {
	char a1[50];
	char buf[50];
	pCreateFile pcreatefile;
	pWriteFile pwritefile;
	LPDWORD result;
}rcode;

DWORD GetProcessIdFromName(TCHAR *sProcName)
{
	DWORD dwFlags = TH32CS_SNAPPROCESS;
	DWORD dwProcessID = 0;
	BOOL fOk;
	int i = 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(dwFlags, dwProcessID);
	PROCESSENTRY32 pe = { sizeof(pe) };

	fOk = Process32First(hSnapshot, &pe);
	int nLen = _tcslen(sProcName);

	do
	{
		if (_tcsnicmp(pe.szExeFile, sProcName, nLen) == 0)
		{
			return pe.th32ProcessID;
		}
	} while ((fOk = Process32Next(hSnapshot, &pe)) != false);

	return 0;
}

DWORD WINAPI proc(LPVOID param) {
	struct remotecode *rcode = (struct remotecode *) param;
	const pCreateFile Createfile = rcode->pcreatefile;
	const pWriteFile Writefile = rcode->pwritefile;
	char *p;
	DWORD r;
	HANDLE h;

	h = (Createfile)((LPCTSTR)rcode->a1, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	for (r = 0, p = rcode->buf; *p; p++, r++);
	(Writefile)(h, rcode->buf, r, &r , NULL);
	return 0;
}

void epil(){}

int inject(TCHAR *cmd) {
	DWORD pid;
	HANDLE hproc;
	remotecode rcode;
	DWORD rsize;
	//for debug
	DWORD errcode;
	TCHAR errmsg[1024];

	while (1) {
		pid = GetProcessIdFromName(cmd);
		if (pid != 0) {
			printf("process id : %d\n\n", pid);
			break;
		}
		printf("execute calc.exe plz :(\n");
		Sleep(1000);
	}

	hproc = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
	if (!hproc) {
		printf("openprocess fail\n");
		return -1;
	}
	sprintf(rcode.a1, "%s", "C:\\Users\\saika\\Desktop\\drop.txt\0");
	sprintf(rcode.buf, "%s", "hell yeah!\0");
	rcode.pcreatefile = (pCreateFile)GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "CreateFileA");
	rcode.pwritefile = (pWriteFile)GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "WriteFile");

	LPVOID daddr = VirtualAllocEx(hproc, NULL, sizeof(remotecode), MEM_COMMIT, PAGE_READWRITE);
	if (!WriteProcessMemory(hproc, daddr, (LPCVOID)&rcode, sizeof(remotecode), NULL)) {
		errcode = GetLastError();
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errcode, 0, errmsg, 1024, NULL);
		printf("WPM1 Error %d : %s\n", errcode, errmsg);
		return -1;
	}
	else {
		printf("WPM1 success : 0x%-32lx\n", daddr);
	}

	rsize = (BYTE *)epil - (BYTE *)proc;
	LPVOID vaddr = VirtualAllocEx(hproc, NULL, rsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!WriteProcessMemory(hproc, vaddr, (LPCVOID)proc, rsize, NULL)) {
		errcode = GetLastError();
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errcode, 0, errmsg, 1024, NULL);
		printf("WPM2 Error %d : %s\n", errcode, errmsg);
		return -1;
	}
	else {
		printf("WPM2 success : 0x%-32lx\n", vaddr);
	}

	HANDLE hThread = CreateRemoteThread(hproc, NULL, 0, (LPTHREAD_START_ROUTINE)vaddr, daddr, CREATE_SUSPENDED, NULL);

	if (!hThread) {
		printf("CRT Failed,,\n");
		return -1;
	}
	else {
		printf("CRT Success\n");
	}

	printf("Resume Thread??\n");
	//getchar();

	ResumeThread(hThread);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hproc);
	return 0;
}

int main() {
	if (inject(L"calc.exe") == -1) {
		printf("Something Wrong,,\n");
		exit(-1);
	}
	printf("Success");
	getchar();
}