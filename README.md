# Ghidra Struct Importer

Allows parsing single C structs that can have dependencies on arbitrary already defined types, circumventing the problem that "Parse C Source" only works if all dependencies of the included header files have been resolved in the same or other included header files.

Based on https://github.com/fmagin/ghidra_scripts/blob/master/ParseDataType.java

### Known issues
- Due to https://github.com/NationalSecurityAgency/ghidra/issues/4903, the current version of this script is only compatible with Ghidra 10.2.x. The reason is that to implement a workaround, this script essentially overwrites the CParser of Ghidra with a modified version from 10.2.x. This will be reverted once the bug is fixed. Until then, using a version other than Ghidra 10.2.x might break Ghidra's C parsing.

### How to install
- Code -> Download ZIP -> Extract anywhere
- Open Ghidra project
- Window -> Script Manager -> Button 'Manage script directories'
- Add (Display file chooser) -> Select extracted folder that contains README.md
- Window -> Script Manager -> Data Types -> ImportCStruct.java -> Run Script (or assign a key)

### Screenshot
![Screenshot](https://github.com/Katharsas/ghidra-struct-importer/blob/main/example_screenshot.png)
