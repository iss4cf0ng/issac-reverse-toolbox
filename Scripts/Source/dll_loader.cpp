//dll_loader.exe
//Author: iss4cf0ng/ISSAC

#include <iostream>
#include <windows.h>

int main(int argc, char* argv[]) {
	if (argc == 1) {
		std::cout << "Usage: load_dll.exe <DLL_PATH>" << std::endl;
		return 1;
	}
	
	std::cout << "DLL: " << argv[1] << std::endl;
	
    LoadLibraryA(argv[1]);
    return 0;
}
