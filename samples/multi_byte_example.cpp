#include <windows.h>
#include <stdio.h>

void main(int argc, char* argv[])
{
	const char *x = "STRING\0";
	int wchars_num = MultiByteToWideChar(CP_UTF8, 0, x, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[wchars_num];
	MultiByteToWideChar(CP_UTF8, 0, x, -1, wstr, wchars_num);
	// do whatever with wstr
	delete[] wstr;

	printf("Finished");
}