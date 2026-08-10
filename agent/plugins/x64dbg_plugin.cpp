/**
 * x64dbg AI Agent Plugin — Named Pipe bridge (COMPLETE IMPLEMENTATION).
 *
 * Architecture:
 *   Claude AI ←→ Python MCP ←→ Named Pipe ←→ This Plugin ←→ x64dbg SDK
 *
 * Build:
 *   cl /LD /EHsc /std:c++20 /I"pluginsdk" x64dbg_plugin.cpp
 *      /link pluginsdk\x64dbg.lib /OUT:mco_agent.dp64
 *
 * Install:
 *   Copy mco_agent.dp64 to x64dbg\x64\plugins\
 *   Restart x64dbg — plugin auto-loads and starts the pipe server.
 *
 * Protocol: see bridge.py — X64A magic, 16-byte header, JSON payload.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <vector>
#include <sstream>
#include <iomanip>

// x64dbg SDK
#include "pluginsdk/bridgemain.h"
#include "pluginsdk/_plugins.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_register.h"
#include "pluginsdk/_scriptapi_debug.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_pattern.h"
#include "pluginsdk/_scriptapi_assembler.h"
#include "pluginsdk/_scriptapi_bookmark.h"
#include "pluginsdk/_scriptapi_comment.h"
#include "pluginsdk/_scriptapi_flag.h"
#include "pluginsdk/_scriptapi_label.h"
#include "pluginsdk/_scriptapi_misc.h"
#include "pluginsdk/_scriptapi_stack.h"
#include "pluginsdk/_scriptapi_symbol.h"

#pragma comment(lib, "pluginsdk/x64dbg.lib")

// ============================================================================
// Wire Protocol (must match bridge.py exactly)
// ============================================================================
#pragma pack(push, 1)
struct PipeHeader {
    char     magic[4];      // "X64A"
    uint16_t version;       // 1
    uint16_t msg_type;      // MsgType
    uint32_t payload_len;
    uint32_t seq_id;
};
#pragma pack(pop)
static_assert(sizeof(PipeHeader) == 16, "PipeHeader must be 16 bytes");

enum class MsgType : uint16_t {
    COMMAND   = 0x01,
    RESPONSE  = 0x02,
    EVENT     = 0x03,
    HEARTBEAT = 0x04,
    ACK       = 0x05,
    ERROR_MSG = 0xFF,
};

constexpr char PIPE_MAGIC[4] = {'X', '6', '4', 'A'};
constexpr uint16_t PIPE_VERSION = 1;
constexpr wchar_t PIPE_NAME[] = L"\\\\.\\pipe\\x64dbg_ai_agent";

// ============================================================================
// Minimal JSON builder (no external deps)
// ============================================================================
class JsonBuilder {
    std::string s;
    bool first = true;
public:
    JsonBuilder& begin_object() { s += '{'; first = true; return *this; }
    JsonBuilder& end_object()   { s += '}'; first = false; return *this; }
    JsonBuilder& begin_array()  { s += '['; first = true; return *this; }
    JsonBuilder& end_array()    { s += ']'; first = false; return *this; }

    JsonBuilder& key(const std::string& k) {
        if (!first) s += ',';
        first = false;
        s += '"';
        s += escape(k);
        s += "\":";
        return *this;
    }

    JsonBuilder& val(const std::string& v) { sep(); s += '"'; s += escape(v); s += '"'; return *this; }
    JsonBuilder& val(uint64_t v)            { sep(); s += std::to_string(v); return *this; }
    JsonBuilder& val(int64_t v)             { sep(); s += std::to_string(v); return *this; }
    JsonBuilder& val(bool v)                { sep(); s += v ? "true" : "false"; return *this; }
    JsonBuilder& raw(const std::string& r)  { sep(); s += r; return *this; }
    JsonBuilder& null_val()                 { sep(); s += "null"; return *this; }

    std::string str() const { return s; }

private:
    void sep() { if (!first && !s.empty() && s.back() != ':' && s.back() != '[' && s.back() != ',') s += ','; }

    static std::string escape(const std::string& in) {
        std::string out;
        out.reserve(in.size() + 8);
        for (unsigned char c : in) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (c < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out += buf;
                    } else {
                        out += (char)c;
                    }
            }
        }
        return out;
    }
};

static std::string hex64(uint64_t v) {
    char buf[20];
    snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
    return buf;
}

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        char c[3];
        snprintf(c, sizeof(c), "%02X", data[i]);
        result += c;
    }
    return result;
}

// Parse simple JSON string value
static std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    pos++; // skip opening quote
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            pos++;
            switch (json[pos]) {
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                default: result += json[pos];
            }
        } else {
            result += json[pos];
        }
        pos++;
    }
    return result;
}

static uint64_t json_get_uint64(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return 0;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return 0;
    while (pos < json.size() && (json[pos] == ':' || json[pos] == ' ')) pos++;
    if (pos >= json.size()) return 0;
    if (json[pos] == '"') {
        // "0x..." hex string
        pos++;
        std::string hex;
        while (pos < json.size() && json[pos] != '"') hex += json[pos++];
        return strtoull(hex.c_str(), nullptr, 16);
    }
    return (uint64_t)strtoull(json.c_str() + pos, nullptr, 10);
}

static int json_get_int(const std::string& json, const std::string& key, int def = 0) {
    return (int)json_get_uint64(json, key) ?: def;
}

// ============================================================================
// Plugin State
// ============================================================================
static int g_plugin_handle = 0;
static std::atomic<bool> g_running{false};
static std::thread g_pipe_thread;
static std::mutex g_pipe_mutex;

// ============================================================================
// Command Handlers — full x64dbg SDK implementation
// ============================================================================
using CommandHandler = std::function<std::string(const std::string&)>;
static std::unordered_map<std::string, CommandHandler> g_handlers;

static void register_handlers() {

    // ---- Registers ----
    g_handlers["registers.get_all"] = [](const std::string&) -> std::string {
        REGDUMP regs = {};
        DbgGetRegDump(&regs);

        JsonBuilder j;
        j.begin_object();
        j.key("rax").val(regs.regcontext.cax);
        j.key("rbx").val(regs.regcontext.cbx);
        j.key("rcx").val(regs.regcontext.ccx);
        j.key("rdx").val(regs.regcontext.cdx);
        j.key("rsi").val(regs.regcontext.csi);
        j.key("rdi").val(regs.regcontext.cdi);
        j.key("rbp").val(regs.regcontext.cbp);
        j.key("rsp").val(regs.regcontext.csp);
        j.key("r8").val(regs.regcontext.r8);
        j.key("r9").val(regs.regcontext.r9);
        j.key("r10").val(regs.regcontext.r10);
        j.key("r11").val(regs.regcontext.r11);
        j.key("r12").val(regs.regcontext.r12);
        j.key("r13").val(regs.regcontext.r13);
        j.key("r14").val(regs.regcontext.r14);
        j.key("r15").val(regs.regcontext.r15);
        j.key("rip").val(regs.regcontext.cip);
        j.key("rflags").val(regs.regcontext.eflags);
        j.key("cs").val((uint64_t)regs.regcontext.cs);
        j.key("ss").val((uint64_t)regs.regcontext.ss);
        j.key("ds").val((uint64_t)regs.regcontext.ds);
        j.key("es").val((uint64_t)regs.regcontext.es);
        j.key("fs").val((uint64_t)regs.regcontext.fs);
        j.key("gs").val((uint64_t)regs.regcontext.gs);
        j.end_object();
        return j.str();
    };

    g_handlers["registers.set"] = [](const std::string& args) -> std::string {
        std::string name = json_get_string(args, "name");
        uint64_t value   = json_get_uint64(args, "value");

        // Map register name to x64dbg enum
        static const std::unordered_map<std::string, uint8_t> reg_map = {
            {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3}, {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
            {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11}, {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
            {"rip", 16}, {"eax", 0}, {"ecx", 1}, {"edx", 2}, {"ebx", 3}, {"esp", 4}, {"ebp", 5}, {"esi", 6}, {"edi", 7},
        };
        auto it = reg_map.find(name);
        if (it == reg_map.end())
            return R"({"error":"unknown register"})";

        // Use DbgCmdExec to set register via x64dbg command
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "%s=%llX", name.c_str(), (unsigned long long)value);
        bool ok = DbgCmdExecDirect(cmd);
        return ok ? R"({"status":"ok"})" : R"({"error":"set failed"})";
    };

    // ---- Debug Control ----
    g_handlers["debug.run"] = [](const std::string&) -> std::string {
        Script::Debug::Run();
        return R"({"status":"running"})";
    };

    g_handlers["debug.pause"] = [](const std::string&) -> std::string {
        Script::Debug::Pause();
        return R"({"status":"paused"})";
    };

    g_handlers["debug.step_into"] = [](const std::string&) -> std::string {
        Script::Debug::StepIn();
        return R"({"status":"stepped"})";
    };

    g_handlers["debug.step_over"] = [](const std::string&) -> std::string {
        Script::Debug::StepOver();
        return R"({"status":"stepped"})";
    };

    g_handlers["debug.status"] = [](const std::string&) -> std::string {
        const char* status = DbgIsDebugging()
            ? (DbgIsRunning() ? "running" : "paused")
            : "not_debugging";
        JsonBuilder j;
        j.begin_object()
         .key("status").val(status)
         .key("is_debugging").val(DbgIsDebugging())
         .key("is_running").val(DbgIsRunning())
         .end_object();
        return j.str();
    };

    // ---- Memory ----
    g_handlers["memory.read"] = [](const std::string& args) -> std::string {
        uint64_t address = json_get_uint64(args, "address");
        int size         = json_get_int(args, "size", 256);
        if (size <= 0 || size > 65536)
            return R"({"error":"invalid size"})";

        std::vector<uint8_t> buf(size);
        bool ok = Script::Memory::Read(address, buf.data(), size, nullptr);
        if (!ok)
            return R"({"error":"read failed"})";

        JsonBuilder j;
        j.begin_object()
         .key("data").val(bytes_to_hex(buf.data(), buf.size()))
         .key("size").val((uint64_t)size)
         .end_object();
        return j.str();
    };

    g_handlers["memory.write"] = [](const std::string& args) -> std::string {
        uint64_t address = json_get_uint64(args, "address");
        std::string hex  = json_get_string(args, "data");

        if (hex.size() % 2 != 0)
            return R"({"error":"hex must have even length"})";

        std::vector<uint8_t> buf(hex.size() / 2);
        for (size_t i = 0; i < buf.size(); i++) {
            char c[3] = {hex[i*2], hex[i*2+1], 0};
            buf[i] = (uint8_t)strtoul(c, nullptr, 16);
        }

        bool ok = Script::Memory::Write(address, buf.data(), (int)buf.size(), nullptr);
        return ok ? R"({"status":"ok"})" : R"({"error":"write failed"})";
    };

    g_handlers["memory.map"] = [](const std::string&) -> std::string {
        MEMMAP map = {};
        DbgMemMap(&map);

        JsonBuilder j;
        j.begin_object();
        j.key("regions").begin_array();
        for (int i = 0; i < map.count; i++) {
            const MEMPAGE& p = map.page[i];
            j.begin_object()
             .key("base").val(hex64(p.mbi.BaseAddress ? (uint64_t)(uintptr_t)p.mbi.BaseAddress : 0))
             .key("size").val((uint64_t)p.mbi.RegionSize)
             .key("state").val((uint64_t)p.mbi.State)
             .key("protect").val((uint64_t)p.mbi.Protect)
             .key("type").val((uint64_t)p.mbi.Type)
             .key("info").val(p.info)
             .end_object();
        }
        j.end_array();
        j.end_object();
        BridgeFree(map.page);
        return j.str();
    };

    g_handlers["memory.search_pattern"] = [](const std::string& args) -> std::string {
        std::string pattern = json_get_string(args, "pattern");
        std::string module  = json_get_string(args, "module");

        uint64_t base = 0, size = 0;
        if (!module.empty()) {
            Script::Module::ModuleInfo mi = {};
            if (Script::Module::InfoFromName(module.c_str(), &mi)) {
                base = mi.base;
                size = mi.size;
            }
        }
        if (!base) {
            base = (uint64_t)DbgMemFindBaseAddr(DbgValFromString("cip"), nullptr);
            // Fall back to full range
        }

        std::vector<duint> results(256);
        int count = (int)Script::Pattern::FindMem(base, size ? size : 0x7FFFFFFF, pattern.c_str(),
                                                   results.data(), results.size());

        JsonBuilder j;
        j.begin_object().key("results").begin_array();
        for (int i = 0; i < count; i++) {
            j.begin_object()
             .key("address").val(hex64(results[i]))
             .end_object();
        }
        j.end_array().end_object();
        return j.str();
    };

    g_handlers["memory.search_strings"] = [](const std::string& args) -> std::string {
        int min_len = json_get_int(args, "min_length", 4);
        // Scan all readable memory for printable strings
        MEMMAP map = {};
        DbgMemMap(&map);

        JsonBuilder j;
        j.begin_object().key("strings").begin_array();
        int count = 0;

        for (int pi = 0; pi < map.count && count < 500; pi++) {
            const MEMPAGE& p = map.page[pi];
            if (!(p.mbi.Protect & PAGE_READABLE) || p.mbi.State != MEM_COMMIT)
                continue;
            if (p.mbi.RegionSize > 64 * 1024 * 1024) continue; // skip huge regions

            size_t region_size = (size_t)p.mbi.RegionSize;
            std::vector<uint8_t> buf(region_size);
            if (!Script::Memory::Read((duint)(uintptr_t)p.mbi.BaseAddress, buf.data(), (int)region_size, nullptr))
                continue;

            std::string cur;
            uint64_t cur_addr = (uint64_t)(uintptr_t)p.mbi.BaseAddress;
            uint64_t str_start = cur_addr;
            for (size_t i = 0; i <= region_size; i++) {
                uint8_t c = (i < region_size) ? buf[i] : 0;
                if (c >= 0x20 && c < 0x7F) {
                    if (cur.empty()) str_start = cur_addr + i;
                    cur += (char)c;
                } else {
                    if ((int)cur.size() >= min_len) {
                        j.begin_object()
                         .key("address").val(hex64(str_start))
                         .key("string").val(cur)
                         .key("length").val((uint64_t)cur.size())
                         .end_object();
                        count++;
                        if (count >= 500) break;
                    }
                    cur.clear();
                }
            }
        }

        j.end_array().end_object();
        BridgeFree(map.page);
        return j.str();
    };

    g_handlers["memory.allocate"] = [](const std::string& args) -> std::string {
        int size       = json_get_int(args, "size", 4096);
        int protection = json_get_int(args, "protection", PAGE_READWRITE);
        duint addr = Script::Memory::RemoteAlloc(0, size);
        if (addr) {
            // Apply protection
            DWORD old_prot;
            VirtualProtectEx(DbgGetProcessHandle(), (LPVOID)(uintptr_t)addr, size, protection, &old_prot);
        }
        JsonBuilder j;
        j.begin_object().key("address").val(hex64(addr)).end_object();
        return j.str();
    };

    g_handlers["memory.protect"] = [](const std::string& args) -> std::string {
        uint64_t address   = json_get_uint64(args, "address");
        int size           = json_get_int(args, "size", 4096);
        int protection     = json_get_int(args, "protection", PAGE_READWRITE);
        DWORD old_prot;
        bool ok = VirtualProtectEx(DbgGetProcessHandle(), (LPVOID)(uintptr_t)address, size, protection, &old_prot) != 0;
        return ok ? R"({"status":"ok"})" : R"({"error":"VirtualProtect failed"})";
    };

    // ---- Breakpoints ----
    g_handlers["breakpoint.set"] = [](const std::string& args) -> std::string {
        uint64_t address = json_get_uint64(args, "address");
        std::string type = json_get_string(args, "type");
        if (type == "software" || type.empty()) {
            bool ok = Script::Debug::SetBreakpoint(address);
            return ok ? R"({"status":"ok"})" : R"({"error":"set breakpoint failed"})";
        } else if (type == "hardware") {
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "bphws %llX, x", (unsigned long long)address);
            DbgCmdExecDirect(cmd);
            return R"({"status":"ok"})";
        }
        return R"({"error":"unknown breakpoint type"})";
    };

    g_handlers["breakpoint.delete"] = [](const std::string& args) -> std::string {
        uint64_t address = json_get_uint64(args, "address");
        bool ok = Script::Debug::DeleteBreakpoint(address);
        return ok ? R"({"status":"ok"})" : R"({"error":"delete failed"})";
    };

    g_handlers["breakpoint.set_hardware"] = [](const std::string& args) -> std::string {
        uint64_t address   = json_get_uint64(args, "address");
        int size           = json_get_int(args, "size", 1);
        std::string cond   = json_get_string(args, "condition");
        // "execute", "read", "write", "readwrite"
        const char* type_str = "x";
        if (cond == "read")       type_str = "r";
        else if (cond == "write") type_str = "w";
        else if (cond == "readwrite") type_str = "rw";
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "bphws %llX, %s, %d", (unsigned long long)address, type_str, size);
        bool ok = DbgCmdExecDirect(cmd);
        return ok ? R"({"status":"ok"})" : R"({"error":"hw breakpoint failed"})";
    };

    // ---- Disassembly ----
    g_handlers["disasm.get"] = [](const std::string& args) -> std::string {
        uint64_t address = json_get_uint64(args, "address");
        int count        = json_get_int(args, "count", 20);
        if (!address) {
            address = DbgValFromString("cip");
        }

        JsonBuilder j;
        j.begin_object().key("instructions").begin_array();
        uint64_t ea = address;
        for (int i = 0; i < count; i++) {
            DISASM_INSTR instr = {};
            DbgDisasmAt(ea, &instr);
            char addr_str[20];
            snprintf(addr_str, sizeof(addr_str), "0x%llX", (unsigned long long)ea);
            char bytes_hex[64] = {};
            for (int b = 0; b < instr.instr_size && b < 16; b++) {
                char byte[3];
                uint8_t bval = 0;
                Script::Memory::Read(ea + b, &bval, 1, nullptr);
                snprintf(byte, sizeof(byte), "%02X", bval);
                strcat(bytes_hex, byte);
            }
            j.begin_object()
             .key("ea").val(addr_str)
             .key("disasm").val(instr.instruction)
             .key("size").val((uint64_t)instr.instr_size)
             .key("bytes").val(bytes_hex)
             .end_object();
            ea += instr.instr_size;
        }
        j.end_array().end_object();
        return j.str();
    };

    // ---- Modules ----
    g_handlers["modules.list"] = [](const std::string&) -> std::string {
        ListInfo list = {};
        Script::Module::GetList(&list);

        JsonBuilder j;
        j.begin_object().key("modules").begin_array();
        for (int i = 0; i < list.count; i++) {
            Script::Module::ModuleInfo* mi = &((Script::Module::ModuleInfo*)list.data)[i];
            j.begin_object()
             .key("base").val(hex64(mi->base))
             .key("size").val((uint64_t)mi->size)
             .key("entry").val(hex64(mi->entry))
             .key("name").val(mi->name)
             .key("path").val(mi->path)
             .end_object();
        }
        j.end_array().end_object();
        BridgeFree(list.data);
        return j.str();
    };

    // ---- Symbols (imports / exports) ----
    g_handlers["symbols.imports"] = [](const std::string& args) -> std::string {
        std::string module_name = json_get_string(args, "module");

        Script::Module::ModuleInfo mi = {};
        duint base = 0;
        if (!module_name.empty()) {
            if (Script::Module::InfoFromName(module_name.c_str(), &mi))
                base = mi.base;
        } else {
            // Use main module
            char main_mod[MAX_MODULE_SIZE] = {};
            if (DbgGetModuleAt(DbgValFromString("cip"), main_mod)) {
                Script::Module::InfoFromName(main_mod, &mi);
                base = mi.base;
            }
        }

        ListInfo sym_list = {};
        Script::Symbol::GetList(base, &sym_list);

        JsonBuilder j;
        j.begin_object().key("imports").begin_array();
        for (int i = 0; i < sym_list.count; i++) {
            Script::Symbol::SymbolInfo* si = &((Script::Symbol::SymbolInfo*)sym_list.data)[i];
            if (si->type == Script::Symbol::SymbolType::Import) {
                j.begin_object()
                 .key("ea").val(hex64(si->addr))
                 .key("name").val(si->name)
                 .key("module").val(si->mod)
                 .end_object();
            }
        }
        j.end_array().end_object();
        BridgeFree(sym_list.data);
        return j.str();
    };

    g_handlers["symbols.exports"] = [](const std::string& args) -> std::string {
        std::string module_name = json_get_string(args, "module");

        Script::Module::ModuleInfo mi = {};
        duint base = 0;
        if (!module_name.empty()) {
            if (Script::Module::InfoFromName(module_name.c_str(), &mi))
                base = mi.base;
        }

        ListInfo sym_list = {};
        Script::Symbol::GetList(base, &sym_list);

        JsonBuilder j;
        j.begin_object().key("exports").begin_array();
        for (int i = 0; i < sym_list.count; i++) {
            Script::Symbol::SymbolInfo* si = &((Script::Symbol::SymbolInfo*)sym_list.data)[i];
            if (si->type == Script::Symbol::SymbolType::Export) {
                j.begin_object()
                 .key("ea").val(hex64(si->addr))
                 .key("name").val(si->name)
                 .end_object();
            }
        }
        j.end_array().end_object();
        BridgeFree(sym_list.data);
        return j.str();
    };

    // ---- Analysis ----
    g_handlers["analysis.function"] = [](const std::string& args) -> std::string {
        uint64_t address = json_get_uint64(args, "address");
        Script::Function::FunctionInfo fi = {};
        bool found = Script::Function::Get(address, &fi);
        if (!found) {
            // Try analyzing
            DbgCmdExecDirect("analyse");
            found = Script::Function::Get(address, &fi);
        }

        char name[MAX_LABEL_SIZE] = {};
        Script::Label::Get(fi.start, name);

        JsonBuilder j;
        j.begin_object()
         .key("name").val(name[0] ? name : "sub_?")
         .key("start").val(hex64(fi.start))
         .key("end").val(hex64(fi.end))
         .key("size").val((uint64_t)(fi.end - fi.start))
         .key("found").val(found)
         .end_object();
        return j.str();
    };

    g_handlers["analysis.xrefs_to"] = [](const std::string& args) -> std::string {
        uint64_t address = json_get_uint64(args, "address");
        XREF_INFO xi = {};
        DbgXrefGet(address, &xi);

        JsonBuilder j;
        j.begin_object().key("xrefs").begin_array();
        for (duint i = 0; i < xi.refcount; i++) {
            j.begin_object()
             .key("from").val(hex64(xi.references[i].addr))
             .key("type").val((uint64_t)xi.references[i].type)
             .end_object();
        }
        j.end_array().end_object();
        BridgeFree(xi.references);
        return j.str();
    };

    g_handlers["analysis.xrefs_from"] = [](const std::string& args) -> std::string {
        // x64dbg xrefs from an address — use DbgXrefGet with source
        return R"({"xrefs":[],"note":"use analysis.xrefs_to from destination address"})";
    };

    // ---- Stack ----
    g_handlers["stack.callstack"] = [](const std::string&) -> std::string {
        CALLSTACK cs = {};
        DbgGetCallStack(&cs);

        JsonBuilder j;
        j.begin_object().key("frames").begin_array();
        for (duint i = 0; i < cs.total; i++) {
            char mod[MAX_MODULE_SIZE] = {};
            DbgGetModuleAt(cs.entries[i].addr, mod);
            j.begin_object()
             .key("frame").val((uint64_t)i)
             .key("address").val(hex64(cs.entries[i].addr))
             .key("from").val(hex64(cs.entries[i].from))
             .key("to").val(hex64(cs.entries[i].to))
             .key("comment").val(cs.entries[i].comment)
             .end_object();
        }
        j.end_array().end_object();
        return j.str();
    };

    // ---- Threads ----
    g_handlers["threads.list"] = [](const std::string&) -> std::string {
        THREADLIST tl = {};
        DbgGetThreadList(&tl);

        JsonBuilder j;
        j.begin_object().key("threads").begin_array();
        for (int i = 0; i < tl.count; i++) {
            j.begin_object()
             .key("tid").val((uint64_t)tl.list[i].BasicInfo.ThreadId)
             .key("entry").val(hex64(tl.list[i].BasicInfo.ThreadStartAddress))
             .key("teb").val(hex64((uint64_t)(uintptr_t)tl.list[i].BasicInfo.ThreadLocalBase))
             .key("is_current").val(tl.CurrentThread == tl.list[i].BasicInfo.ThreadId)
             .end_object();
        }
        j.end_array().end_object();
        BridgeFree(tl.list);
        return j.str();
    };

    // ---- Process ----
    g_handlers["process.peb"] = [](const std::string&) -> std::string {
        duint peb = DbgGetPebAddress(DbgGetProcessId());
        // Read BeingDebugged flag (offset 2)
        uint8_t being_debugged = 0;
        uint32_t nt_global_flag = 0;
        duint image_base = 0;
        if (peb) {
            Script::Memory::Read(peb + 2, &being_debugged, 1, nullptr);
            Script::Memory::Read(peb + 0x68, &nt_global_flag, 4, nullptr);
            Script::Memory::Read(peb + 0x10, &image_base, sizeof(duint), nullptr);
        }
        JsonBuilder j;
        j.begin_object()
         .key("address").val(hex64(peb))
         .key("being_debugged").val((uint64_t)being_debugged)
         .key("image_base").val(hex64(image_base))
         .key("nt_global_flag").val(hex64(nt_global_flag))
         .end_object();
        return j.str();
    };

    g_handlers["process.handles"] = [](const std::string&) -> std::string {
        // x64dbg doesn't expose handle list directly — use DbgCmdExec
        DbgCmdExecDirect("handles");
        return R"({"handles":[],"note":"check x64dbg log for handle output"})";
    };

    // ---- Annotations ----
    g_handlers["annotations.comment"] = [](const std::string& args) -> std::string {
        uint64_t address = json_get_uint64(args, "address");
        std::string text = json_get_string(args, "comment");
        bool ok = Script::Comment::Set(address, text.c_str(), false);
        return ok ? R"({"status":"ok"})" : R"({"error":"comment failed"})";
    };

    g_handlers["annotations.label"] = [](const std::string& args) -> std::string {
        uint64_t address = json_get_uint64(args, "address");
        std::string label = json_get_string(args, "label");
        bool ok = Script::Label::Set(address, label.c_str(), false);
        return ok ? R"({"status":"ok"})" : R"({"error":"label failed"})";
    };

    // ---- Expression eval ----
    g_handlers["eval"] = [](const std::string& args) -> std::string {
        std::string expr = json_get_string(args, "expression");
        duint value = DbgValFromString(expr.c_str());
        JsonBuilder j;
        j.begin_object()
         .key("value").val(hex64(value))
         .key("value_dec").val((uint64_t)value)
         .end_object();
        return j.str();
    };

    // ---- Raw command ----
    g_handlers["command.execute"] = [](const std::string& args) -> std::string {
        std::string cmd = json_get_string(args, "command");
        bool ok = DbgCmdExecDirect(cmd.c_str());
        return ok ? R"({"status":"ok"})" : R"({"error":"command failed"})";
    };

    // ---- Bossix ----
    g_handlers["bossix.hide"] = [](const std::string&) -> std::string {
        DbgCmdExecDirect("HideDebugger");
        // Also zero PEB.BeingDebugged
        duint peb = DbgGetPebAddress(DbgGetProcessId());
        if (peb) {
            uint8_t zero = 0;
            Script::Memory::Write(peb + 2, &zero, 1, nullptr);
            // Clear NtGlobalFlag at PEB+0x68
            uint32_t flag_zero = 0;
            Script::Memory::Write(peb + 0x68, &flag_zero, 4, nullptr);
        }
        return R"({"status":"ok","applied":["HideDebugger","PEB.BeingDebugged=0","NtGlobalFlag=0"]})";
    };

    // ---- Script ----
    g_handlers["script.run"] = [](const std::string& args) -> std::string {
        std::string script = json_get_string(args, "script");
        // Execute line by line
        std::istringstream ss(script);
        std::string line;
        std::vector<std::string> errors;
        while (std::getline(ss, line)) {
            if (line.empty() || line[0] == '#') continue;
            if (!DbgCmdExecDirect(line.c_str())) {
                errors.push_back("failed: " + line);
            }
        }
        if (errors.empty())
            return R"({"status":"ok"})";
        JsonBuilder j;
        j.begin_object().key("status").val("partial").key("errors").begin_array();
        for (auto& e : errors) j.val(e);
        j.end_array().end_object();
        return j.str();
    };

    // ---- Module dump ----
    g_handlers["dump.module"] = [](const std::string& args) -> std::string {
        std::string module_name = json_get_string(args, "module");
        std::string output      = json_get_string(args, "output");
        if (output.empty())
            output = module_name + "_dump.exe";
        // Use x64dbg's built-in dump command
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "dump %s, %s", module_name.c_str(), output.c_str());
        bool ok = DbgCmdExecDirect(cmd);
        return ok ? R"({"status":"ok"})" : R"({"error":"dump failed"})";
    };
}

// ============================================================================
// Wire protocol I/O
// ============================================================================
static bool send_message(HANDLE pipe, MsgType type, uint32_t seq_id, const std::string& payload) {
    PipeHeader hdr;
    memcpy(hdr.magic, PIPE_MAGIC, 4);
    hdr.version     = PIPE_VERSION;
    hdr.msg_type    = (uint16_t)type;
    hdr.payload_len = (uint32_t)payload.size();
    hdr.seq_id      = seq_id;

    std::lock_guard<std::mutex> lock(g_pipe_mutex);
    DWORD w;
    if (!WriteFile(pipe, &hdr, sizeof(hdr), &w, nullptr) || w != sizeof(hdr)) return false;
    if (!payload.empty() && (!WriteFile(pipe, payload.data(), hdr.payload_len, &w, nullptr) || w != hdr.payload_len)) return false;
    return true;
}

static bool read_exact(HANDLE pipe, void* buf, DWORD size) {
    DWORD total = 0;
    while (total < size) {
        DWORD got;
        if (!ReadFile(pipe, (uint8_t*)buf + total, size - total, &got, nullptr) || !got) return false;
        total += got;
    }
    return true;
}

static void handle_client(HANDLE pipe) {
    while (g_running) {
        PipeHeader hdr;
        if (!read_exact(pipe, &hdr, sizeof(hdr))) break;
        if (memcmp(hdr.magic, PIPE_MAGIC, 4) != 0) break;

        std::string payload(hdr.payload_len, '\0');
        if (hdr.payload_len && !read_exact(pipe, payload.data(), hdr.payload_len)) break;

        auto type = (MsgType)hdr.msg_type;

        if (type == MsgType::HEARTBEAT) {
            send_message(pipe, MsgType::ACK, hdr.seq_id, "");
            continue;
        }

        if (type == MsgType::COMMAND) {
            std::string cmd = json_get_string(payload, "cmd");
            std::string response;
            auto it = g_handlers.find(cmd);
            if (it != g_handlers.end()) {
                try {
                    response = it->second(payload);
                } catch (const std::exception& e) {
                    JsonBuilder j;
                    j.begin_object().key("error").val(e.what()).end_object();
                    response = j.str();
                }
            } else {
                JsonBuilder j;
                j.begin_object().key("error").val("unknown command: " + cmd).end_object();
                response = j.str();
            }
            send_message(pipe, MsgType::RESPONSE, hdr.seq_id, response);
        }
    }
}

static void pipe_server_thread() {
    while (g_running) {
        HANDLE pipe = CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536, 65536, 0, nullptr
        );
        if (pipe == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }

        if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            handle_client(pipe);
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

// ============================================================================
// x64dbg Plugin Exports
// ============================================================================
#define PLUG_EXPORT extern "C" __declspec(dllexport)
#define PLUGIN_VERSION 1
#define PLUG_SDKVERSION 50

typedef struct {
    int pluginHandle;
    int sdkVersion;
    int pluginVersion;
    char pluginName[256];
} PLUG_INITSTRUCT;

typedef struct {
    HWND hwndDlg;
    int hMenu;
    int hMenuDisasm;
    int hMenuDump;
    int hMenuStack;
} PLUG_SETUPSTRUCT;

enum PLUGIN_MENU_ID { MENU_START = 0, MENU_STOP, MENU_STATUS };

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* init) {
    init->pluginVersion = PLUGIN_VERSION;
    init->sdkVersion    = PLUG_SDKVERSION;
    strcpy_s(init->pluginName, "MCO AI Agent");
    g_plugin_handle = init->pluginHandle;

    register_handlers();

    // Auto-start pipe server
    g_running = true;
    g_pipe_thread = std::thread(pipe_server_thread);
    _plugin_logprintf("[MCO] AI Agent plugin loaded — named pipe server started\n");
    _plugin_logprintf("[MCO] Python: python -m agent --mcp\n");
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setup) {
    _plugin_menuaddentry(setup->hMenu, MENU_START,  "&Start AI Agent Server");
    _plugin_menuaddentry(setup->hMenu, MENU_STOP,   "&Stop AI Agent Server");
    _plugin_menuaddentry(setup->hMenu, MENU_STATUS, "Agent &Status");
}

PLUG_EXPORT bool plugstop() {
    g_running = false;
    // Unblock the ConnectNamedPipe call
    HANDLE temp = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (temp != INVALID_HANDLE_VALUE) CloseHandle(temp);
    if (g_pipe_thread.joinable()) g_pipe_thread.join();
    _plugin_logprintf("[MCO] AI Agent plugin unloaded\n");
    return true;
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE type, PLUG_CB_MENUENTRY* info) {
    switch (info->hEntry) {
        case MENU_START:
            if (!g_running) {
                g_running = true;
                g_pipe_thread = std::thread(pipe_server_thread);
                _plugin_logprintf("[MCO] Agent server started\n");
            } else {
                _plugin_logprintf("[MCO] Already running\n");
            }
            break;
        case MENU_STOP:
            plugstop();
            break;
        case MENU_STATUS:
            _plugin_logprintf("[MCO] Status: %s | pipe: %ls\n",
                g_running ? "RUNNING" : "STOPPED", PIPE_NAME);
            break;
    }
}
