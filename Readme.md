# LSASS Memory Dumper 

A C++ tool for capturing and encrypting LSASS process memory dumps, designed to study credential theft techniques



## Key Features
- ✅ In-memory dump capture via `MiniDumpWriteDump` callback
- ✅ XOR encryption (configurable key) before disk write

## Technical Workflow
1. **Privilege Check**
   - Verifies admin/SYSTEM rights using `OpenProcessToken`
   - Enables `SeDebugPrivilege` for process access

2. **Process Discovery**
   - Locates LSASS PID via `CreateToolhelp32Snapshot`

3. **Capture LSASS Memory In-Memory**
   - Uses `MiniDumpWriteDump` with custom callback
   - Stores dump in heap-allocated buffer

4. **XOR Encrypt Dump Buffer**
   - XOR-encrypts buffer (key: `0xAA`)
   - Writes to `encrypted_lsass.dmp`
