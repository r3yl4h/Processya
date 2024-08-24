use std::ffi::{c_char, CStr};
use std::fs::File;
use std::{io, mem};
use std::io::Write;
use winapi::shared::minwindef::LPVOID;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::*;
use winapi::um::winnt::*;
use crate::OPT;
use crate::utils::*;




pub unsafe fn dump_section(outfile: &mut File, h_proc: HANDLE, sectionv: &[IMAGE_SECTION_HEADER], base_addr: u64) -> Result<(), io::Error> {
    let mut pos_file = outfile.metadata()?.len() as u32;
    for sec in sectionv {
        let real_addr = sec.VirtualAddress as u64 + base_addr;
        let mut old_protect = 0;
        let mut name_byte = sec.Name;
        let name = CStr::from_ptr(name_byte.as_mut_ptr() as *mut c_char).to_string_lossy().to_string();
        let mut rs = true;
        if VirtualProtectEx(h_proc, real_addr as LPVOID, *sec.Misc.VirtualSize() as usize, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            rs = false;
            eprintln!("{YELLOW}Failed to remove memory protection for {name} section : {:#x} : {}{RESET}", real_addr, io::Error::last_os_error());
            let mut mem_info = mem::zeroed();
            if VirtualQueryEx(h_proc, real_addr as LPVOID, &mut mem_info, mem::size_of::<MEMORY_BASIC_INFORMATION>()) == 0 {
                eprintln!("{RED}Failed to query memory information for {name} section : {:#x} : {}{RESET}", real_addr, io::Error::last_os_error());
                pos_file = outfile.metadata()?.len() as u32;
                continue
            }
            if mem_info.Protect != PAGE_READONLY && mem_info.Protect != PAGE_READWRITE && mem_info.Protect != PAGE_EXECUTE_READ && mem_info.Protect != PAGE_EXECUTE_READWRITE
                && mem_info.Protect != PAGE_EXECUTE_WRITECOPY {
                eprintln!("{RED}failure when changing the memory protection of {name} section and it does not allow reading{RESET}");
                pos_file = outfile.metadata()?.len() as u32;
                continue
            }
        }

        if pos_file != sec.PointerToRawData {
            if pos_file < sec.VirtualAddress {
                outfile.write_all(&vec![0u8;(sec.VirtualAddress - pos_file) as usize])?;
                println!("{GREEN} align section of - 0x{:<4x} byte in file, begin: {:#08x} {:<8}{RESET}", sec.VirtualAddress - pos_file, outfile.metadata()?.len(), name);
            }else {
                eprintln!("{RED}the section {name} has been misaligned and is not where it should be : pos file {:#x} - ptr2raw : {:#x}{RESET}", pos_file, sec.VirtualAddress);
                CloseHandle(h_proc);
                std::process::exit(1);
            }
        }

        if OPT.zero_bss && sec.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            outfile.write_all(&vec![0u8;sec.SizeOfRawData as usize])?;
        }else {
            let mut sec_content = vec![0u8;sec.SizeOfRawData as usize];
            let mut byte_read = 0;
            if ReadProcessMemory(h_proc, real_addr as LPVOID, sec_content.as_mut_ptr() as LPVOID, sec.SizeOfRawData as usize, &mut byte_read) == 0 {
                eprintln!("{RED}Failed to read content of {name} section : {}{RESET}", io::Error::last_os_error());
            }
            outfile.write_all(&sec_content)?;
        }
        pos_file = outfile.metadata()?.len() as u32;
        if rs && VirtualProtectEx(h_proc, real_addr as LPVOID, *sec.Misc.VirtualSize() as usize, old_protect, &mut old_protect) == 0 {
            eprintln!("{YELLOW}failed to restore memory protect for section {name} (protection is on PAGE_EXECUTE_READWRITE) : {} {RESET}", io::Error::last_os_error());
        }
    }
    Ok(())
}