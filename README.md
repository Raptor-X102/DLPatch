# Live Patching (dlpatch)

Live Patching is a runtime library replacement tool for Linux processes. It allows you to replace shared libraries or individual functions in a running process without restarting it. This is useful for hotfixes, A/B testing, or upgrading functionality on the fly.

## Overview

The tool attaches to a target process using `ptrace`, injects shellcode to load new libraries, and redirects function calls from the original library to the new one. It supports both full library replacement and fine‑grained function‑level patching. All changes are tracked and can be rolled back. The patching state is persisted to disk so that it survives a restart of the patching tool itself.

## Key Features

- **Replace entire libraries** – Load a new version of a shared library and redirect all calls from the old library to the new one.
- **Replace individual functions** – Patch only specific functions, leaving the rest of the library intact.
- **Rollback** – Revert patches to restore the original library or function behaviour. You can rollback a single function or the whole library.
- **Unload unused libraries** – Automatically unload library copies that are no longer referenced by any active function.
- **State persistence** – Saves the patching state to `~/.dlpatch/state/<pid>.json`. After a restart of `dlpatch` the state is restored, so you can continue managing patches.
- **Multi‑thread safe** – Freezes threads outside the target library before applying patches, ensuring no thread is executing code being modified.
- **Remote code injection** – Uses `ptrace` and custom shellcode to execute `dlopen`/`dlclose` in the target process.
- **GOT and JMP patching** – Chooses the appropriate patching method based on function size:
  - Small functions (< 16 bytes) are patched via GOT (Global Offset Table) redirection.
  - Larger functions are patched with a 5‑byte relative jump (JMP) at the function prologue.
- **Automatic cleanup daemon** – A background daemon periodically checks for unreferenced libraries and unloads them.

## Implementation Details

- **Architecture**: The core logic is implemented in the `DL_Manager` class, which is split into multiple `.ipp` files for better maintainability.
- **ELF parsing**: The tool parses the dynamic symbol table and GOT entries of loaded libraries to find function addresses and patchable locations.
- **Function tracking**: A global `function_providers_` map keeps track of which library currently provides each patched function. This map is the source of truth for determining active libraries.
- **Thread freezing**: Before any memory write, all threads of the target process are stopped and checked to be outside the library being modified. If any thread is inside, the operation is retried.
- **Shellcode**: Custom x86‑64 shellcode is written into the target process to call `dlopen` and `dlclose`. The shellcode uses the `syscall` instruction found in `libc` to perform memory allocations.

## Requirements

- **Operating System**: Linux (only)
- **Architecture**: x86‑64 (currently the only supported architecture; contributions for ARM, etc., are welcome)
- **Permissions**: The user must have the ability to `ptrace` the target process (usually requires the same user or `sudo`). The target process must be running.
- **Dependencies**: 
  - C++17 compiler
  - `libelf` and `libdw` (for ELF parsing)
  - `nlohmann/json` (for state serialization)
  - `ptrace` system calls (must be enabled on the system)

## Usage

The tool is invoked with the command `dlpatch` followed by a subcommand:

```bash
dlpatch list <pid>
```
List all loaded libraries in the target process and their current status (original/replacement, active/inactive).

```bash
dlpatch symbols <pid> <library_pattern>
```
List all exported functions in a library matching the given pattern (e.g., `libc.so`).

```bash
dlpatch replace <pid> <target_lib> <new_lib> [function]
```
Replace the target library with the new library. If a function name is provided, only that single function is patched; otherwise, all functions are patched ("all").

```bash
dlpatch rollback <pid> <lib_path> [function]
```
Rollback patches applied to the specified library. If a function name is given, only that function is rolled back; otherwise, the whole library is restored.

```bash
dlpatch unload <pid> <lib_path>
```
Unload a library that is no longer active (not providing any functions and not referenced by other libraries). Original libraries cannot be unloaded.

```bash
dlpatch status <pid>
```
Print detailed status of all tracked libraries, including base addresses, handles, patched functions, and backup information.

## Limitations

- **x86‑64 only** – The tool currently works only on x86‑64. Porting to other architectures would require implementing architecture‑specific parts (register access, shellcode, syscall invocation).
- **No kernel‑space support** – Patching is done entirely in userspace; the tool does not modify kernel structures.
- **Function size detection** – For functions that are not exported with size information, the tool assumes a minimum size of 5 bytes (enough for a JMP patch). This may fail for very small functions.
- **Partial rollback semantics** – When a function is rolled back, the tool currently does not automatically deactivate the library that provided it if that library still provides other active functions. This is by design but may be confusing.
- **Not tested on heavily optimized code** – The tool has been tested on simple shared libraries; its behaviour on heavily optimized or stripped binaries is not guaranteed.
- **Security** – Using `ptrace` on a running process can interfere with debuggers and may be blocked by security mechanisms. You may need to adjust system settings.

## Future Improvements

- **Architecture support** – Add support for ARM, AArch64, and RISC‑V.
- **Better function‑level dependency tracking** – Currently, library activation is based on the global function provider map. When a function is rolled back, the original library becomes active only if it is the last patched function. A more granular tracking could automatically activate the correct library even when multiple functions are patched.
- **Automatic rollback of unused libraries** – Enhance the daemon to not only unload libraries but also rollback functions that are no longer needed.
- **Integration with debuggers** – Allow the tool to coexist with `gdb` by detaching and re‑attaching.
- **Integration with libunwind** – Tool will analyse stack not by euristic parameters.
- **Testing on real‑world applications** – Validate the tool on larger, multi‑threaded applications (e.g., web servers, databases).

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
