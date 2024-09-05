# processya - Process-Code-Dumper
  this is a small random project that I made, it allows you to dump the code of a running process and put it in a new pe file with some nice options and that's it, please be lenient
  
# Usage
```
Processya - Process-Code-Dumper 1.0.0

USAGE:
    Processya.exe [FLAGS] [OPTIONS] --output <outpath>

FLAGS:
    -a, --dump-all       dump with all other dump options enabled (parent dump child dump etc)
    -c, --dump-child     to dump all child processes
    -m, --dump-module    dump the code of all modules that were loaded in the process
    -r, --dump-parent    to dump the parents process
    -h, --help           Prints help information
    -V, --version        Prints version information
    -z, --zero-bss       resets all sections that should contain uninitialized data to 0 in the file

OPTIONS:
    -n, --name <name>         to choose the target process with its name, example: --name "test.exe"
    -o, --output <outpath>    to specify the folder that will contain the output file
    -p, --pid <pid>           to choose the target process with its pid
```
