#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifdef _WIN64
#include <WinBase.h>
#endif

// Define bool
typedef int bool;
#define true 1
#define false 0

const char* _version = "0.0.5";

const char* _banner = " __________.__        ___.  __________\n"
" \\______   \\  |   ____\\_ |__\\______   \\__ __  ____   ____   ___________     \n"
"  |    |  _/  |  /  _ \\| __ \\|       _/  |  \\/    \\ /    \\_/ __ \\_  __ \\  \n"
"  |    |   \\  |_(  <_> ) \\_\\ \\    |   \\  |  /   |  \\   |  \\  ___/|  | \\/ \n"
"  |______  /____/\\____/|___  /____|_  /____/|___|  /___|  /\\___  >__|          \n"
"         \\/                \\/       \\/           \\/     \\/     \\/    \n\n"
"                                                                     %s    \n\n";


void banner() {
	system("cls");
	printf(_banner, _version);
	return;
}

LPVOID process_file(char* inputfile_name, bool jit, int offset, bool debug, LPVOID lpAddress) {
	LPVOID lpBase;
	FILE* file;
	unsigned long fileLen;
	char* buffer;
	DWORD dummy;

	file = fopen(inputfile_name, "rb");

	if (!file) {
		printf(" [!] Error: Unable to open %s\n", inputfile_name);

		return (LPVOID)NULL;
	}

	printf(" [*] Reading file...\n");
	fseek(file, 0, SEEK_END);
	fileLen = ftell(file); //Get Length

	printf(" [*] File Size: 0x%04x\n", fileLen);
	fseek(file, 0, SEEK_SET); //Reset

	fileLen += 1;

	buffer = (char*)malloc(fileLen); //Create Buffer
	fread(buffer, fileLen, 1, file);
	fclose(file);

	printf(" [*] Allocating Memory...\n");

	lpBase = VirtualAlloc(lpAddress, fileLen, 0x3000, 0x40);

	// Only perform verification in case lpAddress != NULL.
	if (lpAddress && lpBase != lpAddress) {
		printf(" [!] Unable to allocate buffer@0x%p\n", lpAddress);
		return (LPVOID)NULL;
	}

	printf(" [*] Allocated!\n");
	printf(" [*]   |-Base: 0x%08x\n", (int)(size_t)lpBase);
	printf(" [*] Copying input data...\n");

	CopyMemory(lpBase, buffer, fileLen);
	return lpBase;
}

void execute(LPVOID base, int offset, bool nopause, bool jit, bool debug)
{
	LPVOID shell_entry;

#ifdef _WIN64
	DWORD   thread_id;
	HANDLE  thread_handle;
	const char msg[] = " [*] Navigate to the Thread Entry and set a breakpoint. Then press any key to resume the thread.\n";
#else
	const char msg[] = " [*] Navigate to the EP and set a breakpoint. Then press any key to jump to the shellcode.\n";
#endif

	shell_entry = (LPVOID)((UINT_PTR)base + offset);

#ifdef _WIN64

	printf(" [*] Creating suspended thread...\n");
	thread_handle = CreateThread(
		NULL,          // Attributes
		0,             // Stack size (Default)
		shell_entry,         // Thread EP
		NULL,          // Arguments
		0x4,           // Create suspended
		&thread_id);   // Thread identifier

	if (thread_handle == NULL) {
		printf(" [!] Error creating thread...");
		return;
	}
	printf(" [*] Created thread: [%d]\n", thread_id);
	printf(" [*] Thread entry: 0x%016x\n", (int)(size_t)shell_entry);

#endif

	if (nopause == false) {
		printf("%s", msg);
		getchar();
	}
	else
	{
		if (jit == true) {
			// Force an exception by making the first byte not executable.
			// This will cause
			DWORD oldp;

			printf(" [*] Removing EXECUTE access to trigger exception...\n");

			VirtualProtect(shell_entry, 1 , PAGE_READWRITE, &oldp);
		}
	}

#ifdef _WIN64
	printf(" [*] Resuming thread..\n");
	ResumeThread(thread_handle);
#else
	printf(" [*] Entry: 0x%08x\n", (int)(size_t)shell_entry);
	printf(" [*] Jumping to shellcode\n");
	__asm jmp shell_entry;
#endif
}

void print_help() {
	printf(" [!] Error: No file!\n\n");
	printf("     Required args: <inputfile>\n\n");
	printf("     Optional Args:\n");
	printf("         --offset <offset>      The offset to jump into.\n");
	printf("         --base <base address>  The base address of the region to allocate in hex.\n");
	printf("         --nopause              Don't pause before jumping to shellcode. Danger!!! \n");
	printf("         --jit                  Forces an exception by removing the EXECUTE permission from the alloacted memory.\n");
	printf("         --debug                Verbose logging.\n");
	printf("         --version              Print version and exit.\n\n");
}

int main(int argc, char* argv[])
{
	LPVOID lpBase = NULL;
	LPVOID lpAddress = NULL;
	int i;
	int offset = 0;
	bool nopause = false;
	bool debug = false;
	bool jit = false;
	char* nptr;

	banner();

	if (argc < 2) {
		print_help();
		return -1;
	}

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--offset") == 0) {
			printf(" [*] Parsing offset...\n");
			i = i + 1;
			if (strncmp(argv[i], "0x", 2) == 0) {
			    offset = strtol(argv[i], &nptr, 16);
            }
			else {
			    offset = strtol(argv[i], &nptr, 10);
			}
		}
		else if (strcmp(argv[i], "--base") == 0) {
			i++;
			lpAddress = (LPVOID)strtoul(argv[i], &nptr, 16);
		}
		else if (strcmp(argv[i], "--nopause") == 0) {
			nopause = true;
		}
		else if (strcmp(argv[i], "--jit") == 0) {
			jit = true;
			nopause = true;
		}
		else if (strcmp(argv[i], "--debug") == 0) {
			debug = true;
		}
		else if (strcmp(argv[i], "--version") == 0) {
			printf("Version: %s", _version);
		}
	}

	// We assume the file is provided at the end of the commandline.
	char *file_name = argv[argc - 1];
	printf(" [*] Using file: %s \n", file_name);

	struct stat stat_buf;
	if (stat (file_name, &stat_buf) == 0) {
		printf(" [*] %s can be read.\n", file_name);
	} else {
		printf(" [!] Unable to access file %s.\n", file_name);
		printf(" [!] Exiting...");
		return -1;
	}

	lpBase = process_file(file_name, jit, offset, debug, lpAddress);
	if (lpBase == NULL) {
		printf(" [!] Exiting...");
		return -1;
	}
	printf(" [*] Using offset: 0x%08x\n", offset);
	execute(lpBase, offset, nopause, jit, debug);
	printf("Pausing - Press any key to quit.\n");
	getchar();
	return 0;
}