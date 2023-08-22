#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define SHT_STRTAB 3
#define SHT_SYMTAB 2
#define ET_EXEC 2
#define NOT_FOUND -2

char *getsectionsymtab(FILE *file, Elf64_Shdr *sec_header , char *strngtable, Elf64_Ehdr *header);
char *getsectionstrtab(FILE *file, Elf64_Shdr *section_header, Elf64_Ehdr *header, char *sh_string_table);
int lookingForSection(char *secname ,Elf64_Shdr *secheader, char *strngtable , Elf64_Ehdr *header);
Elf64_Sym *getSymb(char *sym_input , char *str_table ,Elf64_Shdr *sym_header, char *sym_table);

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
		FILE *file = fopen(exe_file_name, "r");
	if(!file)
	{
		*error_val = -3; // takes precedence over other cases
		return 0;
	}
	Elf64_Ehdr header;
	fread(&header, sizeof(header), 1, file);
	int is_exec = (header.e_type == ET_EXEC);
	//checking if the type is exe
	if (!is_exec)
	{
		*error_val = -3; // takes precedence over other cases
		return 0;
	}

	Elf64_Shdr section_header[header.e_shentsize * header.e_shnum]; //array of section headers
	fseek(file, header.e_shoff, SEEK_SET); // move to section header offset
	fread(section_header, header.e_shentsize, header.e_shnum, file); // read the section headers into the array


	Elf64_Shdr strtab = section_header[header.e_shstrndx];
	char *sh_string_table = (char *)malloc(strtab.sh_size);
	fseek(file, strtab.sh_offset, SEEK_SET);
	fread(sh_string_table, strtab.sh_size, 1, file);


	char *symbol_table = getsectionsymtab(file, section_header, sh_string_table, &header);
	char *string_table = getsectionstrtab(file, section_header, &header, sh_string_table);

	int symb_ind = lookingForSection(".symtab" , section_header, sh_string_table , &header);
	Elf64_Shdr symtab_header = section_header[symb_ind];

	Elf64_Sym *symb = getSymb(symbol_name , string_table ,&symtab_header , symbol_table );
	if (symb == NULL)
	{
		*error_val = -1;
	}else {
		if (ELF64_ST_BIND(symb->st_info) != 1)
		{
			*error_val = -2;
		}else{
			if (symb->st_shndx == SHN_UNDEF)
			{
				*error_val = -4;
			}else{
				*error_val = 1;
				unsigned long ret_addr = symb->st_value;
				free(sh_string_table);
				free(symbol_table);
				free(string_table);
				fclose(file);
				return ret_addr  ;
				//return (unsigned long) symbol->st_value ;
			}
		}
	}
	free(sh_string_table);
	free(symbol_table);
	free(string_table);
	fclose(file);
	return 0 ;
}

char *getsectionsymtab(FILE *file, Elf64_Shdr *sec_header , char *strngtable, Elf64_Ehdr *header){
	int num = lookingForSection(".symtab" , sec_header , strngtable ,  header);
	if(num >= 0)
	{
		Elf64_Shdr temp_sec_header = sec_header[num];
		char *section = (char *)malloc(temp_sec_header.sh_size);
		fseek(file, temp_sec_header.sh_offset, SEEK_SET);
		fread(section, temp_sec_header.sh_size, 1, file);
		return section;
	}
	return NULL;
}

char *getsectionstrtab(FILE *file, Elf64_Shdr *section_header, Elf64_Ehdr *header, char *sh_string_table){
	int index = lookingForSection(".strtab" , section_header,sh_string_table,  header);
	if(index < 0)
	{
		return NULL;
	}
	Elf64_Shdr sec_header = section_header[index];
	char *section = (char *)malloc(sec_header.sh_size);
	fseek(file, sec_header.sh_offset, SEEK_SET);
	fread(section, sec_header.sh_size, 1, file);
	return section;
}

int lookingForSection(char *secname ,Elf64_Shdr *secheader, char *strngtable , Elf64_Ehdr *header){
	for (int currSection = 0; currSection < header->e_shnum; currSection ++)
	{
		if (strcmp(strngtable + secheader[currSection].sh_name, secname))
		{
			continue ;
		}
		return currSection ;
	}
	return NOT_FOUND ;
}

Elf64_Sym *getSymb(char *sym_input , char *str_table ,Elf64_Shdr *sym_header, char *sym_table){
	Elf64_Sym *saved_symbl = NULL;
	for (int j = 0; j < sym_header->sh_size / sym_header->sh_entsize ; j++ )
	{
		Elf64_Sym *curr_symbl = (Elf64_Sym *)( sym_table + (j * sym_header->sh_entsize) );
		char *sym_name = str_table + curr_symbl->st_name;

		if (strcmp(sym_name, sym_input) != 0)
		{
			continue ;
		}
		if (ELF64_ST_BIND(curr_symbl->st_info) != 1)
			{
				saved_symbl = curr_symbl;
				continue ;
			}
			saved_symbl = curr_symbl;
			break ;
	}
	return saved_symbl;
}
	

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err >= 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}