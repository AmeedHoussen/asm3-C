ENTRY(_hw3_unicorn) ; 

PHDRS
{
	text PT_LOAD AT(0x400000) FLAGS ( 2 | 1 ) ;
	data PT_LOAD AT(0x60000) FLAGS ( 2 | 4) ;
	rodata PT_LOAD AT(0x80000000) FLAGS ( 4 | 1 ) ;
}

SECTIONS
{
  . = 0x400000 ; 
  .text :{ *(.text) } :text

  .data 0x60000 :{ *(.data) *(.bss)} :data

  . = 0x80000000 ;
  .rodata :{ *(.rodata) } :rodata
}

EXTERN (purple white) ;