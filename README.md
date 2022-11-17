# Ghidra Struct Importer

Allows parsing single C structs that can have dependencies on arbitrary already defined types, circumventing the problem that "Parse C Source" only works if all dependencies of the included header files have been resolved in the same or other included header files.

Based on https://github.com/fmagin/ghidra_scripts/blob/master/ParseDataType.java

### Known issues
- Hitting the "parse" button might modify the project's types even when the "apply" button was not pressed
- Dot not parse datatypes with names that already exist anywhere, regardless of in which category, otherwise type might end up with wrong name

### Screenshot
![Screenshot](https://github.com/Katharsas/ghidra-struct-importer/blob/main/example_screenshot.png)
