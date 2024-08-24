use std::ffi::CStr;
use std::fs::OpenOptions;
use winapi::shared::minwindef::LPVOID;
use winapi::um::handleapi::CloseHandle;

use winapi::um::tlhelp32::PROCESSENTRY32;
use winapi::um::winnt::HANDLE;
use crate::OPT;
use crate::process::get_base_addr;
use crate::utils::*;



pub fn dump_file(entry: PROCESSENTRY32, h_proc: HANDLE) {
    unsafe {
        let filename = CStr::from_ptr(entry.szExeFile.as_ptr()).to_string_lossy().to_string();
        println!("\n\x1b[0;35mDump {filename}{RESET}");
        let outpath = format!("{}\\{}", OPT.outpath.to_string_lossy(), filename.replace(".", &format!("_dump{}.", entry.th32ProcessID)));
        let mut outfile = match OpenOptions::new().write(true).read(true).create(true).truncate(true).open(&outpath) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("{RED}Failed to create file {outpath} : {e}{RESET}");
                std::process::exit(1);
            }
        };
        let base_addr = get_base_addr(entry.th32ProcessID).unwrap_or_else(|e| {
            eprintln!("{RED}{e}{RESET}");
            std::process::exit(1)
        });


        let sectionv = crate::dump::header::dump_header(h_proc, base_addr, &mut (0 as LPVOID), &mut outfile).unwrap_or_else(|e| {
            eprintln!("{RED}Failed to read header of process in output file : {e}{RESET}");
            CloseHandle(h_proc);
            std::process::exit(1)
        });

        crate::dump::section::dump_section(&mut outfile, h_proc, &sectionv, base_addr).unwrap_or_else(|e|{
            eprintln!("{RED}Error to dump section : {e}{RESET}");
            CloseHandle(h_proc);
            std::process::exit(1)
        });
    }
}



