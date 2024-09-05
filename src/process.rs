use crate::utils::RESET;
use crate::utils::RED;
use std::ffi::CStr;
use std::io;
use std::mem;
use winapi::shared::minwindef::HMODULE;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::psapi::EnumProcessModules;
use winapi::um::tlhelp32::*;
use winapi::um::winnt::HANDLE;


fn find_proc<F: Fn(&PROCESSENTRY32) -> bool>(func_e: F) -> Result<PROCESSENTRY32, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("Error creating snapshot: {}", io::Error::last_os_error()));
        }
        let mut entry: PROCESSENTRY32 = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return Err(format!("Error retrieving the first process: {}", io::Error::last_os_error()));
        }
        loop {
            if func_e(&entry) {
                CloseHandle(snapshot);
                return Ok(entry);
            }
            if Process32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snapshot);
    }
    Err("Process not found".to_string())
}



pub fn get_procentry_with_pid(pid: u32) -> Result<PROCESSENTRY32, String> {
    find_proc(|entry| entry.th32ProcessID == pid)
}




pub fn get_procentry_with_name(process_name: &str) -> Result<PROCESSENTRY32, String> {
    find_proc(|entry| {
        unsafe { CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy() == process_name }
    })
}





pub fn get_base_addr(pid: u32) -> Result<u64, String> {
    unsafe {
        let hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if hsnapshot == INVALID_HANDLE_VALUE {
            return Err(format!("Error creating snapshot: {}", io::Error::last_os_error()));
        }
        let mut me32: MODULEENTRY32 = mem::zeroed();
        me32.dwSize = mem::size_of::<MODULEENTRY32>() as u32;
        if Module32First(hsnapshot, &mut me32) == 0 {
            return Err(format!("Error in Module32First: {}", io::Error::last_os_error()));
        }
        Ok(me32.modBaseAddr as u64)
    }
}




pub unsafe fn get_modules_process(h_proc: HANDLE) -> Result<Vec<HMODULE>, String> {
    let mut modules: Vec<HMODULE> = vec![mem::zeroed::<HMODULE>(); 1024];
    let mut cb_needed = 0;
    unsafe {
        if EnumProcessModules(h_proc, modules.as_mut_ptr(), (1024 * mem::size_of::<HMODULE>()) as u32, &mut cb_needed) == 0 {
            return Err(format!("{RED}failed to enum modules of process : {}{RESET}", io::Error::last_os_error()))
        }
    }
    let module_count = (cb_needed / mem::size_of::<HMODULE>() as u32) as usize;
    modules.truncate(module_count);
    Ok(modules)
}