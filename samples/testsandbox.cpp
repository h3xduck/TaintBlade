#include <windows.h>
#include <stdlib.h>
#include <stdio.h>


int __cdecl main(int argc, char** argv)
{
	FILETIME fileTime;
	GetSystemTimeAsFileTime(&fileTime);
	DWORD pid = GetCurrentProcessId();
	DWORD tick = GetTickCount();
	LARGE_INTEGER li;
	QueryPerformanceCounter(&li);
	LONGLONG perf = li.QuadPart;
	
	ULONGLONG ufiletime = (((ULONGLONG)fileTime.dwHighDateTime) << 32) + fileTime.dwLowDateTime;
	ULONGLONG upid = (ULONGLONG)pid;
	ULONGLONG utick = (ULONGLONG)tick;
	ULONGLONG uperf = (ULONGLONG)perf;

	printf("%I64u, %I64u, %I64u, %I64u\n", ufiletime, upid, utick, uperf);

	ULONGLONG res = ufiletime ^ upid ^ utick ^ uperf & 0xffffffffffff;
	printf("%I64u\n", res);
	ULONGLONG resneg = ~res;
	printf("%I64u\n", resneg);
}