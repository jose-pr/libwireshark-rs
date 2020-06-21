# Wireshark Dissector Plugin written on Rust
Compiles completly on rust no need for C. Bindings generated in a windows x64 machine but would probably work in other systems. 
If nore the vscode script can build them just from the header files. 

Do need to specify the libwireshark path on the build.rs for the dissector. Also need to generate (at least for windows) the .lib for the libwireshark.dll which I was able to do with the ddl2lib.bat script included.

## TODO
* Better Documentation
* Macros/Methods for generating prefenrence from struct, and correctly handles accessing a static global config object
** one_cell? Simple Arc/Mutext?
* Macros/Methods for generating Protocol columns.
* ..... 
