use std::{io, ptr};
use std::ffi::{c_char, CStr};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_VM_OPERATION, PROCESS_VM_READ};
use crate::dump;
use crate::utils::*;

pub fn dump_child(entry: PROCESSENTRY32) {
    match find_child(entry.th32ProcessID) {
        Ok(child_proc) => {
            for child in child_proc {
                let mut child = child;
                let new_name = unsafe {CStr::from_ptr(child.szExeFile.as_ptr()).to_string_lossy()}.replace(".", "_child.");
                let new_name = new_name.as_bytes();
                if new_name.len() < 260 {
                    unsafe {
                        ptr::copy(new_name.as_ptr() as *const c_char, child.szExeFile.as_mut_ptr(), new_name.len());
                    }
                    child.szExeFile[new_name.len()] = 0;
                }
                unsafe {
                    let h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME, 0, child.th32ProcessID);
                    dump::dump::dump_file(child, h_proc);
                }
            }
        }
        Err(e) => eprintln!("{e}"),
    }
}



pub fn find_child(parent_pid: u32) -> Result<Vec<PROCESSENTRY32>, String> {
    let mut child_proc = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("{RED}failed to create snapshot for dump child process: {}{RESET}", io::Error::last_os_error()))
        }
        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32ParentProcessID == parent_pid {
                    child_proc.push(entry)
                }
                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }else {
            return Err(format!("{RED}failed to get info of first process : {}{RESET}", io::Error::last_os_error()));
        }
    }
    if child_proc.len() != 0 {
        Ok(child_proc)
    }else {
        Err(String::from("the process does not contain children"))
    }
}