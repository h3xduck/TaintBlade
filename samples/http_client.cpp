#include <iostream>
#include <Windows.h>
#include <WinINet.h>

#pragma comment(lib, "wininet.lib")

int main()
{
    HINTERNET hInternet = InternetOpenA("MyApp", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        std::cerr << "Failed to open Internet" << std::endl;
        return 1;
    }

    HINTERNET hUrl = InternetOpenUrlA(hInternet, "https://www.google.com", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hUrl == NULL) {
        std::cerr << "Failed to open URL" << std::endl;
        InternetCloseHandle(hInternet);
        return 1;
    }

    char buffer[1024];
    DWORD bytesRead;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        std::cout.write(buffer, bytesRead);
    }


    char* comp = "www";
    if (strncmp(buffer, comp, 3) == 0)
    {
        printf("WWW!");
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    return 0;
}