#include <iostream>
#include <fstream>
#include <Windows.h>

PIMAGE_EXPORT_DIRECTORY GetExportDir(HMODULE module_name)
{

	//Get Module base and cast it to a dos header
	uint64_t image_base = (uint64_t)module_name;
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_base;
	//
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS)(image_base + dos_header->e_lfanew);

	return (PIMAGE_EXPORT_DIRECTORY)(image_base + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

}

int main()
{

	//Get a handle to ntdll. No need to load it into mem as every exe has ntdll loaded.
	const HMODULE h_module{ GetModuleHandleA("ntdll.dll") };

	//Image base for arithmetic
	const uint64_t module_base = (uint64_t)h_module;

	//Retrieve our export directory for iteration of exports
	PIMAGE_EXPORT_DIRECTORY export_dir = GetExportDir(h_module);

	//Get pointers to the export names, ords and addresses
	PDWORD exportname_list = (PDWORD)(module_base + export_dir->AddressOfNames);
	PDWORD funcaddress_list = (PDWORD)(module_base + export_dir->AddressOfFunctions);
	PWORD ordinal = (PWORD)(module_base + export_dir->AddressOfNameOrdinals);

	//Create and open our files
	std::ofstream dump_file("syscall_indexes.h");
	//Write standard headers to our file
	dump_file << "#pragma once\n" << "#include <unordered_map>\n" << "std::unordered_map<const char*, int8_t> syscall_indices = {\n";

	//Iterate through all export names
	for (int32_t i{ 0 }; i < export_dir->NumberOfNames; ++i)
	{

		std::string current_name = (char*)((uint64_t)h_module + exportname_list[i]);
		
		if (current_name.substr(0, 2) == "Nt")
		{
			//Get the function address
			uint64_t func_address = module_base + funcaddress_list[ordinal[i]];
			//Because these are syscalls the syscall index will be at func + 0x4
			uint32_t syscall_index = *(uint32_t*)(func_address + 0x4);
			//I read some other people's dumps and they dont go higher the 480h~ I just rounded up to 500h
			if(syscall_index < 0x500)
				dump_file << "\t{ \"" << current_name.c_str() << "\", 0x" << std::hex << syscall_index << " },\n";

		}	

	}

	dump_file << "};";
	//Push our changes
	dump_file.flush();
	//Close the file
	dump_file.close();
	
	return 0;

}