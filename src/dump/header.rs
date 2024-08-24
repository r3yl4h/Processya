use std::fs::File;
use std::{io, mem, ptr};
use std::io::{Seek, SeekFrom, Write};
use winapi::shared::minwindef::LPVOID;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::ReadProcessMemory;
use crate::dump::{Bitness, HeaderNt};
use winapi::um::winnt::*;
use crate::utils::*;


pub trait OptHeader {
    fn set_file_alignment(&mut self);
    fn set_size_of_code(&mut self, new_size: u32);
    fn set_size_of_init(&mut self, new_size: u32);
    fn set_size_of_uninit(&mut self, new_size: u32);
    fn set_size_of_image(&mut self, new_size: u32);
    fn get_size_of_struct_opt(&self) -> usize;
}



impl OptHeader for IMAGE_OPTIONAL_HEADER32 {
    fn set_file_alignment(&mut self) {
        if self.FileAlignment < self.SectionAlignment {
            self.FileAlignment = self.SectionAlignment;
            println!("\x1b[0;36m new section align  : {:#x}", self.SectionAlignment);
        }
    }
    fn set_size_of_code(&mut self, new_size: u32) {
        if new_size > self.SizeOfCode {
            self.SizeOfCode = new_size;
            println!("\x1b[0;36m new size of code  : {:#x}", self.SizeOfCode);
        }
    }
    fn set_size_of_init(&mut self, new_size: u32) {
        if self.SizeOfInitializedData < new_size {
            self.SizeOfInitializedData = new_size;
            println!("\x1b[0;36m new size of init  : {:#x}", new_size);
        }
    }
    fn set_size_of_uninit(&mut self, new_size: u32) {
        if self.SizeOfUninitializedData < new_size {
            self.SizeOfUninitializedData = new_size;
            println!("\x1b[0;36m new size of uinit : {:#x}", new_size);
        }
    }
    fn set_size_of_image(&mut self, new_size: u32) {
        if self.SizeOfImage < new_size {
            self.SizeOfImage = new_size;
            println!("\x1b[0;36m new size of image : {:#x}", new_size);
        }
    }
    fn get_size_of_struct_opt(&self) -> usize { mem::size_of::<IMAGE_NT_HEADERS32>() }
}


impl OptHeader for IMAGE_OPTIONAL_HEADER64 {
    fn set_file_alignment(&mut self) {
        if self.FileAlignment < self.SectionAlignment {
            self.FileAlignment = self.SectionAlignment;
            println!("\x1b[0;36m new section align : {:#x}", self.SectionAlignment);
        }
    }

    fn set_size_of_code(&mut self, new_size: u32) {
        if new_size > self.SizeOfCode {
            self.SizeOfCode = new_size;
            println!("\x1b[0;36m new size of code  : {:#x}", self.SizeOfCode);
        }
    }

    fn set_size_of_init(&mut self, new_size: u32) {
        if self.SizeOfInitializedData < new_size {
            self.SizeOfInitializedData = new_size;
            println!("\x1b[0;36m new size of init  : {:#x}", new_size);
        }
    }

    fn set_size_of_uninit(&mut self, new_size: u32) {
        if self.SizeOfUninitializedData < new_size {
            self.SizeOfUninitializedData = new_size;
            println!("\x1b[0;36m new size of uinit : {:#x}", new_size);
        }
    }

    fn set_size_of_image(&mut self, new_size: u32) {
        if self.SizeOfImage < new_size {
            self.SizeOfImage = new_size;
            println!("\x1b[0;36m new size of image : {:#x}", new_size);
        }
    }

    fn get_size_of_struct_opt(&self) -> usize { mem::size_of::<IMAGE_NT_HEADERS64>() }
}



pub unsafe fn fix_nt_head(outfile: &mut File, e_lafnew: i32, header_nt: &HeaderNt, sectionv: &[IMAGE_SECTION_HEADER]) -> Result<(), io::Error> {
    let (mut size_code, mut size_uninit, mut size_init) = (0, 0, 0);
    let size_image = sectionv.last().unwrap().VirtualAddress + sectionv.last().unwrap().Misc.VirtualSize();

    for sec in sectionv {
        if sec.Characteristics & IMAGE_SCN_CNT_CODE != 0 {
            size_code += *sec.Misc.VirtualSize();
        }
        if sec.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            size_init += *sec.Misc.VirtualSize();
        }
        if sec.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            size_uninit += *sec.Misc.VirtualSize();
        }
    }

    let opt_pos = e_lafnew + 0x18;
    let last_pos = outfile.metadata()?.len();

    match header_nt.bitness {
        Bitness::X32 => {
            let mut nt32 = *(header_nt.nt_header.0 as *const IMAGE_NT_HEADERS32);
            update_optional_header(&mut nt32.OptionalHeader, size_code, size_init, size_uninit, size_image);
            outfile.write_header(opt_pos, last_pos, nt32.OptionalHeader)?;
        },
        Bitness::X64 => {
            let mut nt64 = *(header_nt.nt_header.0 as *const IMAGE_NT_HEADERS64);
            update_optional_header(&mut nt64.OptionalHeader, size_code, size_init, size_uninit, size_image);
            outfile.write_header(opt_pos, last_pos, nt64.OptionalHeader)?;
        },
    }

    if let Some(offs) = recl_symptr_table(header_nt.nt_header.0 as *const IMAGE_NT_HEADERS32, sectionv) {
        let ptr_sym = e_lafnew + 0xc;
        outfile.seek_write(ptr_sym as u64, last_pos, &offs.to_le_bytes())?;
        println!("new symbol ptr    : {:#x}", offs);
    }
    Ok(())
}



unsafe fn update_optional_header<T: OptHeader>(opt_header: &mut T, size_code: u32, size_init: u32, size_uninit: u32, size_image: u32, ) {
    opt_header.set_file_alignment();
    opt_header.set_size_of_code(size_code);
    opt_header.set_size_of_init(size_init);
    opt_header.set_size_of_uninit(size_uninit);
    opt_header.set_size_of_image(size_image);
}


trait WriteHeader {
    fn write_header<T: OptHeader>(&mut self, opt_pos: i32, last_pos: u64, opt_header: T) -> io::Result<()>;
    fn seek_write(&mut self, pos: u64, last_pos: u64, data: &[u8]) -> io::Result<()>;
}


impl WriteHeader for File {
    fn write_header<T: OptHeader>(&mut self, opt_pos: i32, last_pos: u64, opt_header: T) -> io::Result<()> {
        let data = unsafe { std::slice::from_raw_parts(ptr::addr_of!(opt_header) as *const u8, opt_header.get_size_of_struct_opt()) };
        self.seek_write(opt_pos as u64, last_pos, data)
    }

    fn seek_write(&mut self, pos: u64, last_pos: u64, data: &[u8]) -> io::Result<()> {
        self.seek(SeekFrom::Start(pos))?;
        self.write_all(data)?;
        self.seek(SeekFrom::Start(last_pos))?;
        Ok(())
    }
}


pub unsafe fn recl_symptr_table(nt_h: *const IMAGE_NT_HEADERS32, sectionv: &[IMAGE_SECTION_HEADER]) -> Option<u32> {
    let sym_ptr = (*nt_h).FileHeader.PointerToSymbolTable;
    if sym_ptr != 0 {
        sectionv.iter().find_map(|sec| {
            if sec.PointerToRawData <= sym_ptr && sec.PointerToRawData + sec.SizeOfRawData >= sym_ptr {
                Some(sym_ptr - sec.PointerToRawData + sec.VirtualAddress)
            } else {
                None
            }
        })
    }else {
        None
    }
}











pub unsafe fn dump_header(h_proc: HANDLE, base_addr: u64, addr: &mut LPVOID, outfile: &mut File) -> Result<Vec<IMAGE_SECTION_HEADER>, io::Error> {
    let mut h_nt: HeaderNt = HeaderNt::default();
    let mut dos_header: IMAGE_DOS_HEADER = mem::zeroed();
    if ReadProcessMemory(h_proc, base_addr as LPVOID, &mut dos_header as *mut _ as LPVOID, mem::size_of::<IMAGE_DOS_HEADER>(), &mut 0) == 0 {
        eprintln!("{RED}Failed to read IMAGE_DOS_HEADER : {}{RESET}", io::Error::last_os_error());
        std::process::exit(1)
    }
    *addr = (base_addr + dos_header.e_lfanew as u64 + 4) as LPVOID;
    let mut machine = 0u16;
    if ReadProcessMemory(h_proc, *addr as LPVOID, &mut machine as *mut _ as LPVOID, 2, &mut 0) == 0 {
        eprintln!("{RED}Failed to read IMAGE_NT_HEADER : {}", io::Error::last_os_error());
        CloseHandle(h_proc);
        std::process::exit(1);
    }

    *addr = (*addr as u64 - 4) as LPVOID;

    match machine {
        IMAGE_FILE_MACHINE_I386  => {
            let mut nt32: IMAGE_NT_HEADERS32 = mem::zeroed();
            if ReadProcessMemory(h_proc, *addr, &mut nt32 as *mut _ as LPVOID, mem::size_of::<IMAGE_NT_HEADERS32>(), &mut 0) == 0 {
                eprintln!("{RED}Failed to read IMAGE_NT_HEADER32 : {}{RESET}", io::Error::last_os_error());
                CloseHandle(h_proc);
                std::process::exit(1);
            }
            h_nt.nt_header.0 = ptr::addr_of_mut!(nt32) as LPVOID;
            h_nt.bitness = Bitness::X32;
            *addr = (*addr as usize + mem::size_of::<IMAGE_NT_HEADERS32>()) as LPVOID;
        },

        IMAGE_FILE_MACHINE_AMD64 => {
            let mut nt64: IMAGE_NT_HEADERS64 = mem::zeroed();
            if ReadProcessMemory(h_proc, *addr, &mut nt64 as *mut _ as LPVOID, mem::size_of::<IMAGE_NT_HEADERS64>(), &mut 0) == 0 {
                eprintln!("{RED}Failed to read IMAGE_NT_HEADER64 : {}{RESET}", io::Error::last_os_error());
                CloseHandle(h_proc);
                std::process::exit(1);
            }
            h_nt.nt_header.0 = ptr::addr_of_mut!(nt64) as LPVOID;
            h_nt.bitness = Bitness::X64;
            *addr = (*addr as usize + mem::size_of::<IMAGE_NT_HEADERS64>()) as LPVOID;
        },
        _ => {
            eprintln!("{RED}the target machine of this file is not supported{RESET}");
            CloseHandle(h_proc);
            std::process::exit(1)
        }
    }
    let size_all = (*addr as u64 - base_addr) as usize;
    let mut header_byte = vec![0u8; size_all];
    if ReadProcessMemory(h_proc, base_addr as LPVOID, header_byte.as_mut_ptr() as LPVOID, size_all, &mut 0) == 0 {
        eprintln!("{RED}Failed to read all header of file : {}{RESET}", io::Error::last_os_error());
        CloseHandle(h_proc);
        std::process::exit(1)
    }
    outfile.write_all(&header_byte)?;
    let num_sec = *((h_nt.nt_header.0 as u64 + 0x6) as *const u16);
    let mut sectionv = vec![mem::zeroed::<IMAGE_SECTION_HEADER>(); num_sec as usize];
    let size_secb = mem::size_of::<IMAGE_SECTION_HEADER>() * num_sec as usize;
    if ReadProcessMemory(h_proc, *addr, sectionv.as_mut_ptr() as LPVOID, size_secb, &mut 0) == 0 {
        eprintln!("{RED}Failed to read section header of process : {}{RESET}", io::Error::last_os_error());
        CloseHandle(h_proc);
        std::process::exit(1)
    }
    fix_nt_head(outfile, dos_header.e_lfanew, &h_nt, &sectionv)?;
    sectionv.iter_mut().for_each(|sec| {
        sec.PointerToRawData = sec.VirtualAddress;
        sec.SizeOfRawData = *sec.Misc.VirtualSize();
    });
    outfile.write_all(std::slice::from_raw_parts(sectionv.as_ptr() as *const u8, size_secb))?;
    Ok(sectionv)
}