#include<Windows.h>
#include<winternl.h>
#include<stdio.h>


void GetKernel32BaseAddress() {
	PPEB pPeb;		// PEB
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PLIST_ENTRY pListEntry;

	pPeb = (PPEB)__readfsdword(0x30);
	pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->InMemoryOrderModuleList.Flink;
	pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink;

	pListEntry = pListEntry->Flink;
	pListEntry = pListEntry->Flink;

	pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pListEntry->Flink);

	printf("Kernel32.dll : 0x%p\n", pLdrDataTableEntry->Reserved2[0]);
}


int main(void) {

	GetKernel32BaseAddress();

	return 0;
}
