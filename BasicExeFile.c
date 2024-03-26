#include <Windows.h>

int main() {
	while (TRUE) {
		MessageBoxA(NULL, "Not Hooked", "Not Hooked", MB_YESNO);
		Sleep(3000);
	}
	return 0;
}