# rverse

A set of libraries and utilities to facilitate reverse engineering

### TODOs

* TEST TEST TEST (with rspec, ideally)
* Fix the ObjC module to not assume little-endian byte ordering
* Detect nonatomic properties (appears to need code introspection, but very simple code introspection: would be sufficient to look for objc_set/getproperty)
* Decode the additional information in the dysymtab load command, to support other kinds of relocations and dynamic linker behavior
* Let the ObjC type descriptor parser understand ObjC++
* Have the ObjC module detect ObjC1/1.5/2 and search for structures accordingly
* Output ObjC information to a metaformat (for eventual computer reasoning) which could then be output to ObjC syntax if desired
* Test C / ObjC grammars and implement header/prototype parsing for them, to avoid redundant information being added to header output (and eventually, to build a database of parameter and return types to aid in simple decompilation of function calls and associated variables)
* Add a C++ grammar and integrate it into ObjC if necessary
* Consider adding support for gcc extensions to C/ObjC/C++ as most of the headers we'll be dealing with come from gcc/g++
* Abstract away the Image class and have MachO simply return subclasses of it
* Fix the Image virtual memory IO object to prevent reading past the edge of segment boundaries
* Reorder directories to make more sense

### Long-term plans

* Add a c module that allows dumping of c functions. This would need code introspection, to varying degrees. The simplest step is to detect the number of arguments a function takes. With register/stack tracing in a function (usually possible), it amounts to (in ARM) counting how many of r0-r3 and parts of the stack are read before they're set. A degree deeper is to try to infer the argument types by a database of known library functions. For example, if I have a function f that takes an argument x, and I see that one of the first thing f does with argument x is pass it in as the second parameter to strcpy, I can usually infer that the type of x is char *. Care would need to be taken to resolve conflicts in argument usage.
* Dump c++ binaries. This is facilitated by the fact that the symbols describe the argument types (see c++filt) and the classes have a degree of introspective ability.
* Allow users to pass in "sample" programs that call the functions and use the classes in the specified binary, to improve dumping. In c binaries (defined as a binary that has no ObjC or C++ info in it), this would allow detection of whether a function returns a value or not.
* Allow listing "intelligent cross-references", that not only tell you where a given function is called, but also, through register and memory tracing, any closed-form expressions possible to infer for its arguments.
* Rule the world
### Dependencies

* Treetop

### How to use

For now, just run rverse.rb with the Objective C 2.0 binary you'd like to dump as its parameter. It will output the header contents to stdout (if you're lucky). If you specify a second parameter, it will redirect stdout to the file specified by that parameter.