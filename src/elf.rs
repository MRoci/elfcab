use bytemuck::Pod;
use bytemuck::Zeroable;

pub const ELF64_HDR_SIZE: usize = 64;
pub const ELFMAG0: u8 = 127; // 0x7f
pub const ELFMAG1: u8 = 69; // E
pub const ELFMAG2: u8 = 76; // L
pub const ELFMAG3: u8 = 70; // F
pub const ELFCLASS64: u8 = 2; // ELF64

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct elf64_hdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}
unsafe impl Zeroable for elf64_hdr {}
unsafe impl Pod for elf64_hdr {}

pub const ELF64_PHDR_SIZE: usize = 56;
pub const PT_LOAD: u32 = 1;
pub const PT_NOTE: u32 = 4;
pub const PF_R: u32 = 4;
pub const PF_W: u32 = 2;
pub const PF_X: u32 = 1;
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct elf64_phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}
unsafe impl Zeroable for elf64_phdr {}
unsafe impl Pod for elf64_phdr {}

pub const ELF64_SHDR_SIZE: usize = 64;
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct elf64_shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}
unsafe impl Zeroable for elf64_shdr {}
unsafe impl Pod for elf64_shdr {}
