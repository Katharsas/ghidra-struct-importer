# Ghidra Struct Importer

Allows parsing single C structs that can have dependencies on arbitrary already defined types, circumventing the problem that "Parse C Source" only works if all dependencies of the included header files have been resolved in the same or other included header files.

Based on https://github.com/fmagin/ghidra_scripts/blob/master/ParseDataType.java

### Compatibility

- Compatible with Ghidra 10.3 or higher since version 0.2.0
- For Ghidra 10.2 you must use verson 0.1.0 (since it contains a workaround for [this issue](https://github.com/NationalSecurityAgency/ghidra/issues/4903))
- Lower version are untested

### How to install
- [Releases](https://github.com/Katharsas/ghidra-struct-importer/releases) -> Select Release -> Source Code (..) -> Download -> Extract anywhere
- Open Ghidra project
- Window -> Script Manager -> Button 'Manage script directories'
- Add (Display file chooser) -> Select extracted folder that contains README.md
- Window -> Script Manager -> Data Types -> ImportCStruct.java -> Run Script (or assign a key)

### Screenshot
![Screenshot](https://github.com/Katharsas/ghidra-struct-importer/blob/main/example_screenshot.png)
