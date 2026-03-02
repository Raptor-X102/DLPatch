//=============================================================================
// Data structures
//=============================================================================

// Information about a loaded library
struct LibraryInfo {
    std::string path;    // Full path to the library file
    uintptr_t base_addr; // Base address where library is loaded
    size_t size;         // Total size of the library in memory
    bool is_original;    // Whether this is the original library (never unloaded)
    bool is_active;      // Whether this library is currently the target of any patch
    std::vector<std::pair<uintptr_t, uintptr_t>>
        segments; // Memory segments [start, end)

    // Default constructor
    LibraryInfo()
        : base_addr(0)
        , size(0)
        , is_original(false)
        , is_active(false) {}

    // Constructor with basic parameters
    LibraryInfo(const std::string &p, uintptr_t addr, size_t sz)
        : path(p)
        , base_addr(addr)
        , size(sz)
        , is_original(false)
        , is_active(false) {}
};

struct StackInfo {
    uintptr_t start;
    uintptr_t end;
    size_t size;
};

// Tracked library state with rollback data
struct TrackedLibrary {
    std::string path;                           // Library path (used as key)
    uintptr_t handle;                           // Handle returned by dlopen
    uintptr_t base_addr;                        // Base address in memory
    std::vector<std::string> patched_functions; // Functions patched from other libraries
    std::vector<std::string> provided_functions; // All functions this library exports
    std::vector<std::string>
        patched_libraries; // Libraries that were patched to point to this one
    bool is_active;        // Whether this library is currently the target of any patch
    bool is_original;      // Whether this is the original library (never unloaded)
    std::map<std::string, std::vector<uint8_t>>
        saved_original_bytes; // Original bytes for JMP patch rollback
    std::map<std::string, uintptr_t>
        saved_original_got; // Original GOT values for GOT patch rollback

    // Fields for library identification
    time_t mtime;     // File modification time
    size_t file_size; // File size

    // Constructors
    TrackedLibrary()
        : handle(0)
        , base_addr(0)
        , is_active(false)
        , is_original(false)
        , mtime(0)        // Явно инициализируем нулем
        , file_size(0) {} // Явно инициализируем нулем

    TrackedLibrary(const std::string &p,
                   uintptr_t h,
                   uintptr_t addr,
                   const std::string &func)
        : path(p)
        , handle(h)
        , base_addr(addr)
        , is_active(false)
        , is_original(false)
        , mtime(0)       // Явно инициализируем нулем
        , file_size(0) { // Явно инициализируем нулем
        provided_functions.push_back(func);
    }

    TrackedLibrary(const std::string &p,
                   uintptr_t h,
                   uintptr_t addr,
                   const std::vector<std::string> &functions)
        : path(p)
        , handle(h)
        , base_addr(addr)
        , provided_functions(functions)
        , is_active(false)
        , is_original(false)
        , mtime(0)        // Явно инициализируем нулем
        , file_size(0) {} // Явно инициализируем нулем
};

// Symbol information
struct SymbolInfo {
    std::string name;
    uintptr_t addr;
    size_t size;
    int type;       // STT_FUNC, STT_OBJECT, etc.
    int bind;       // STB_GLOBAL, STB_LOCAL, STB_WEAK
    int visibility; // STV_DEFAULT, STV_HIDDEN, STV_PROTECTED

    SymbolInfo(const std::string &n,
               uintptr_t a,
               size_t s,
               int t = STT_FUNC,
               int b = STB_GLOBAL,
               int v = STV_DEFAULT)
        : name(n)
        , addr(a)
        , size(s)
        , type(t)
        , bind(b)
        , visibility(v) {}
};

// Thread context for stop/resume operations
struct ThreadContext {
    pid_t tid;                    // Thread ID
    struct user_regs_struct regs; // Saved registers
};

// Dynamic section information parsed from ELF
struct DynamicInfo {
    uintptr_t strtab = 0;     // DT_STRTAB - string table
    uintptr_t symtab = 0;     // DT_SYMTAB - symbol table
    uintptr_t jmprel = 0;     // DT_JMPREL - PLT relocations
    size_t pltrelsz = 0;      // DT_PLTRELSZ - size of PLT relocations
    uint64_t pltrel_type = 0; // DT_PLTREL - type of relocations (DT_RELA or DT_REL)
    size_t strsz = 0;         // DT_STRSZ - size of string table
    size_t syment = 0;        // DT_SYMENT - size of symbol table entry
    uintptr_t hash = 0;       // DT_HASH - ELF hash table
    uintptr_t gnu_hash = 0;   // DT_GNU_HASH - GNU hash table
};

// Cache structure
struct CachedLibraryData {
    std::vector<SymbolInfo> symbols;              // Cached symbols
    std::map<std::string, uintptr_t> got_entries; // Cached GOT entries by symbol name
    bool parsed;                                  // Whether cache is valid

    // Constructor
    CachedLibraryData()
        : parsed(false) {}
};

enum class LoadResult {
    NOT_FOUND,      // Library not found in tracker or maps
    CHANGED,        // File changed, needs reload
    LOADED_NEW,     // New copy of library was loaded
    USED_EXISTING,  // Existing copy used (file unchanged, but library may be inactive)
    ALREADY_ACTIVE, // Library already active and unchanged - nothing to do
    FAILED          // Failed to load library
};
