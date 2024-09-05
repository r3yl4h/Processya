use crate::dump::*;
use std::ffi::{c_char, CStr};
use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use winapi::shared::minwindef::HMODULE;
use winapi::um::psapi::{GetModuleFileNameExA, GetModuleInformation, MODULEINFO};
use winapi::um::winnt::{HANDLE, LPSTR};
use crate::dump::header::dump_header;
use crate::OPT;

pub fn dump_module(module: HMODULE, h_proc: HANDLE) {
    let mut name;
    let mut module_name = [0u8; 260];
    let mut module_str ;
    unsafe {
        let mut mod_info: MODULEINFO = std::mem::zeroed();
        if GetModuleInformation(h_proc, module, &mut mod_info, std::mem::size_of::<MODULEINFO>() as u32) == 0 {
            eprintln!("{RED}Failed to get module information: {}{RESET}", io::Error::last_os_error());
            return
        }
        let len = GetModuleFileNameExA(h_proc, module, module_name.as_mut_ptr() as LPSTR, 260);
        if len == 0 {
            name = format!("module_{:#x}.dll", mod_info.lpBaseOfDll as u64);
            module_str = name.to_string();
            eprintln!("{YELLOW}Failed to get module name, name for this module is {name}{RESET}");
        } else {
            module_str = CStr::from_ptr(module_name.as_ptr() as *const c_char).to_string_lossy().to_string();
            name = Path::new(&module_str).file_name().unwrap().to_string_lossy().to_string();
            module_str = name.clone();
            name = name.replace(".", &format!("_dump_{:#x}.", mod_info.lpBaseOfDll as u64));
        }
        println!("\n\x1b[0;35mDump {module_str}{RESET}");
        let filepath = format!("{}\\{}", OPT.outpath.to_string_lossy(), name);
        let mut outfile = match OpenOptions::new().write(true).read(true).create(true).truncate(true).open(&filepath) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("{RED}Failed to create file {filepath} : {e}{RESET}");
                std::process::exit(1);
            }
        };
        let mut addr = 0 as LPVOID;
        let sectionv = match dump_header(h_proc, mod_info.lpBaseOfDll as u64, &mut addr, &mut outfile) {
            Ok(sectionv) => sectionv,
            Err(e) => {
                eprintln!("{RED}Failed to dump header : {e}{RESET}");
                return;
            }
        };
        if let Err(e) = section::dump_section(&mut outfile, h_proc, &sectionv, mod_info.lpBaseOfDll as u64) {
            eprintln!("{RESET}Failed to dump section of {module_str} module : {e}{RESET}");
            return
        }
    }
}