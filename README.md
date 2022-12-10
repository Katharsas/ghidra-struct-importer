# Ghidra Struct Importer

Allows parsing single C structs that can have dependencies on arbitrary already defined types, circumventing the problem that "Parse C Source" only works if all dependencies of the included header files have been resolved in the same or other included header files.

Based on https://github.com/fmagin/ghidra_scripts/blob/master/ParseDataType.java

### Known issues
- Parsed datatypes cannot depend on each other unless saved one by one

### Screenshot
![Screenshot](https://github.com/Katharsas/ghidra-struct-importer/blob/main/example_screenshot.png)
