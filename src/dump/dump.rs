use std::ffi::CStr;
use std::fs::OpenOptions;
use winapi::shared::minwindef::LPVOID;

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
                return
            }
        };
        let base_addr = match get_base_addr(entry.th32ProcessID){
            Ok(base) => base,
            Err(e) => {
                eprintln!("{RED}{e}{RESET}");
                return
            }
        };

        let sectionv = match crate::dump::header::dump_header(h_proc, base_addr, &mut (0 as LPVOID), &mut outfile){
            Ok(sectionv) => sectionv,
            Err(e) => {
                eprintln!("{RED}Failed to read header of process in output file : {e}{RESET}");
                return
            }
        };

        if let Err(e) = crate::dump::section::dump_section(&mut outfile, h_proc, &sectionv, base_addr){
            eprintln!("{RED}Error to dump section : {e}{RESET}");
            return
        }
    }
}



