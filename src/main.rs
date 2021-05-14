mod elf;
mod patch;
mod shellcode;

use patch::*;

use std::fs;
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "elfcab",
    about = "inject shellcode into ELF file, jump to original entrypoint"
)]
struct Opt {
    /// target executable
    #[structopt(parse(from_os_str))]
    target: PathBuf,

    /// shellcode file
    #[structopt(parse(from_os_str))]
    shellcode: PathBuf,

    /// output file name  
    #[structopt(short = "o", parse(from_os_str))]
    output: PathBuf,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    let elf_fd = fs::OpenOptions::new().read(true).open(&opt.target)?;

    let mut elf_file = ElfFile::new(&elf_fd)?;

    let mut sc = fs::OpenOptions::new().read(true).open(&opt.shellcode)?;

    elf_file.pt_note_to_pt_load(&mut sc)?;

    let out = elf_file.reflect_changes()?;
    let mut out_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&opt.output)?;
    out_file.write_all(&out)?;
    fs::set_permissions(&opt.output, fs::Permissions::from_mode(0o770))?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run()?;
    Ok(())
}
