pub mod dump_child;
pub mod dump;
mod section;
mod header;
mod module;

use ntapi::ntpsapi::{NtResumeProcess, NtSuspendProcess};
use winapi::shared::minwindef::LPVOID;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_VM_OPERATION, PROCESS_VM_READ};
use crate::Opt;
use crate::utils::*;
use crate::process::{get_modules_process, get_procentry_with_name, get_procentry_with_pid};

pub enum Bitness {
    X32,
    X64,
}

#[derive(Default)]
pub struct HeaderNt {
    pub nt_header: LVOID,
    pub bitness: Bitness,
}

pub struct LVOID(pub LPVOID);

impl Default for LVOID {
    fn default() -> Self {
        LVOID(0 as LPVOID)
    }
}

impl Default for Bitness {
    fn default() -> Self {
        Bitness::X64
    }
}



impl Opt {
    pub fn dump(&mut self) {
        let entry = if let Some(pid) = self.pid {
            get_procentry_with_pid(pid)
        }else if let Some(name) = &self.name {
            get_procentry_with_name(&name)
        }else {
            eprintln!("{RED}No target{RESET}");
            std::process::exit(1)
        };
        if self.dump_all {
            self.set_all_true();
        }
        let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME;

        match entry{
            Ok(entry) => unsafe {
                let h_proc = OpenProcess(access, 0, entry.th32ProcessID);
                let mut rest = NtSuspendProcess(h_proc);
                if rest != 0 {
                    eprintln!("{RED}Failed to suspend process with ntstatus {rest}{RESET}");
                }
                dump::dump_file(entry, h_proc);
                if self.dump_child {
                    dump_child::dump_child(entry)
                }
                if self.dump_parent {
                    match get_procentry_with_pid(entry.th32ParentProcessID) {
                        Ok(entry_p) => {
                            let h_parent = OpenProcess(access, 0, entry.th32ProcessID);
                            let mut rest = NtSuspendProcess(h_parent);
                            if rest != 0 {
                                eprintln!("{RED}Failed to suspend process with ntstatus {rest}{RESET}");
                            }
                            dump::dump_file(entry_p, h_parent);
                            rest = NtResumeProcess(h_parent);
                            if rest != 0 {
                                eprintln!("{RED}Failed to suspend process with ntstatus {rest}{RESET}");
                            }
                        },
                        Err(e) => eprintln!("{RED}{e}{RESET}"),
                    }
                }
                if self.dump_module {
                    match get_modules_process(h_proc) {
                        Ok(modules) => {
                            for module in modules.iter().skip(1) {
                                module::dump_module(*module, h_proc);
                            }
                        },
                        Err(e) => eprintln!("{e}"),
                    }
                }
                rest = NtResumeProcess(h_proc);
                if rest != 0 {
                    eprintln!("{RED}Failed to resume process with ntstatus {rest}{RESET}");
                }
                CloseHandle(h_proc);
            },
            Err(e) => {
                eprintln!("{RED}{e}{RESET}");
                std::process::exit(1)
            }
        }
    }

    fn set_all_true(&mut self) {
        self.dump_child = true;
        self.dump_module = true;
        self.dump_parent = true;
    }
}