use std::path::PathBuf;
use structopt::StructOpt;
use once_cell::sync::Lazy;


mod process;
mod utils;
mod dump;


static mut OPT: Lazy<Opt> = Lazy::new(|| Opt::from_args());

#[derive(StructOpt, Debug)]
#[structopt(name = "Processya - Process-Code-Dumper", version = "1.0.0")]
struct Opt {
    #[structopt(short = "p", long = "pid", help = "to choose the target process with its pid")]
    pub pid: Option<u32>,
    #[structopt(short = "n", long = "name", help = "to choose the target process with its name, example: --name \"test.exe\"")]
    pub name: Option<String>,
    #[structopt(short = "o", long = "output", help = "to specify the folder that will contain the output file")]
    outpath: PathBuf,
    #[structopt(short = "z", long = "zero-bss", help = "resets all sections that should contain uninitialized data to 0 in the file")]
    pub zero_bss: bool,
    #[structopt(short = "c", long = "dump-child", help = "to dump all child processes")]
    pub dump_child: bool,
    #[structopt(short = "r", long = "dump-parent", help = "to dump the parents process")]
    pub dump_parent: bool,
    #[structopt(short="m", long = "dump-module", help = "dump the code of all modules that were loaded in the process")]
    pub dump_module: bool,
    #[structopt(short="a", long = "dump-all", help = "dump with all other dump options enabled (parent dump child dump etc)")]
    pub dump_all: bool
}



fn main() {
    unsafe { OPT.dump() }
}
