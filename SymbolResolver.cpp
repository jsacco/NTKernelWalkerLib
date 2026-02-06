#include "SymbolResolver.hpp"
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>

namespace symres {

using namespace std::string_literals;
static std::wstring GetDefaultSymbolPath()
{
    wchar_t buf[4096] = {};
    DWORD len = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", buf, static_cast<DWORD>(std::size(buf)));
    if (len > 0 && len < std::size(buf)) return { buf, len };
    return L"srv*%SystemRoot%\\Symbols*https://msdl.microsoft.com/download/symbols";
}

std::optional<uint64_t> ResolveSymbolRvaFromFile(const std::wstring& image_path,
                                                 const std::string& symbol_name,
                                                 const std::wstring& symbol_path)
{
    if (!std::filesystem::exists(image_path)) return std::nullopt;

    HANDLE proc = GetCurrentProcess();
    const std::wstring syms = symbol_path.empty() ? GetDefaultSymbolPath() : symbol_path;

    DWORD opts = SymGetOptions();
    opts |= SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS;
    SymSetOptions(opts);

    if (!SymInitializeW(proc, syms.c_str(), FALSE))
        return std::nullopt;

    DWORD64 mod_base = SymLoadModuleExW(proc, nullptr, image_path.c_str(), nullptr, 0, 0, nullptr, 0);
    if (!mod_base)
    {
        SymCleanup(proc);
        return std::nullopt;
    }

    std::optional<uint64_t> rva;
    std::vector<unsigned char> buffer(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t));
    auto* sym = reinterpret_cast<PSYMBOL_INFOW>(buffer.data());
    sym->SizeOfStruct = sizeof(SYMBOL_INFOW);
    sym->MaxNameLen = MAX_SYM_NAME;
    const std::wstring wname(symbol_name.begin(), symbol_name.end());
    if (SymFromNameW(proc, wname.c_str(), sym))
    {
        rva = static_cast<uint64_t>(sym->Address - sym->ModBase);
    }

    SymUnloadModule64(proc, mod_base);
    SymCleanup(proc);
    return rva;
}

std::optional<uint64_t> ResolveNtoskrnlSymbolRva(const std::string& symbol_name,
                                                 const std::wstring& symbol_path)
{
    wchar_t sysdir[MAX_PATH] = {};
    if (!GetSystemDirectoryW(sysdir, MAX_PATH)) return std::nullopt;
    std::filesystem::path ntpath = sysdir;
    ntpath /= L"ntoskrnl.exe";
    return ResolveSymbolRvaFromFile(ntpath.wstring(), symbol_name, symbol_path);
}

// ------------------- Image map + gadget scan helpers -------------------

bool MapImageFile(const std::wstring& path, ImageMapping& img)
{
    img.file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (img.file == INVALID_HANDLE_VALUE) { img.file = nullptr; return false; }

    img.mapping = CreateFileMappingW(img.file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!img.mapping) { CloseHandle(img.file); img.file = nullptr; return false; }

    img.view = static_cast<BYTE*>(MapViewOfFile(img.mapping, FILE_MAP_READ, 0, 0, 0));
    if (!img.view) { CloseHandle(img.mapping); CloseHandle(img.file); img.mapping = nullptr; img.file = nullptr; return false; }

    auto nt = ImageNtHeader(img.view);
    if (!nt) { UnmapViewOfFile(img.view); CloseHandle(img.mapping); CloseHandle(img.file); img.view = nullptr; img.mapping = nullptr; img.file = nullptr; return false; }

    img.size = nt->OptionalHeader.SizeOfImage;
    img.exec_ranges.clear();
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            size_t start = sec->VirtualAddress;
            size_t len = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            size_t end = start + len;
            if (end > img.size) end = img.size;
            img.exec_ranges.push_back({ start, end });
        }
    }
    return true;
}

void UnmapImageFile(ImageMapping& img)
{
    if (img.view) UnmapViewOfFile(img.view);
    if (img.mapping) CloseHandle(img.mapping);
    if (img.file) CloseHandle(img.file);
    img.view = nullptr; img.mapping = nullptr; img.file = nullptr; img.size = 0; img.exec_ranges.clear();
}

// --- tiny decoder to describe short gadgets ---
static const char* kGpr64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

struct DecodedInstr { size_t len{0}; std::string text; bool isRet{false}; bool ok{false}; };

static bool ParseRegFromOpcode(unsigned char rex, unsigned char base, int& regOut)
{
    int idx = base & 0x7;
    if (rex & 0x01) idx |= 0x8; // REX.B
    regOut = idx;
    return idx < 16;
}

static bool ParseRegReg(unsigned char rex, unsigned char modrm, int& reg, int& rm)
{
    reg = ((modrm >> 3) & 7);
    rm = (modrm & 7);
    if (rex & 0x04) reg |= 0x8; // REX.R
    if (rex & 0x01) rm |= 0x8;  // REX.B
    return reg < 16 && rm < 16;
}

static DecodedInstr DecodeOne(const BYTE* p, size_t maxLen)
{
    DecodedInstr d{};
    if (maxLen == 0) return d;
    size_t i = 0; unsigned char rex = 0;
    auto isLegacy = [](unsigned char b) {
        switch (b) { case 0xF0: case 0xF2: case 0xF3: case 0x2E: case 0x36: case 0x3E: case 0x26:
            case 0x64: case 0x65: case 0x66: case 0x67: return true; default: return false; }
    };
    while (i < maxLen && isLegacy(p[i])) i++;
    while (i < maxLen && p[i] >= 0x40 && p[i] <= 0x4F) { rex = p[i]; i++; }
    if (i >= maxLen) return d;
    unsigned char op = p[i++];
    auto finish = [&](std::string t, size_t len, bool ret=false) { d.len=len; d.text=std::move(t); d.isRet=ret; d.ok=true; return d; };
    if (op >= 0x58 && op <= 0x5F) { int r; ParseRegFromOpcode(rex, op, r); return finish("pop "s + kGpr64[r], i); }
    if (op >= 0x50 && op <= 0x57) { int r; ParseRegFromOpcode(rex, op, r); return finish("push "s + kGpr64[r], i); }
    if (op == 0xC3) return finish("ret", i, true);
    if (op == 0xC2 && i + 1 < maxLen) { uint16_t imm = p[i] | (p[i+1] << 8); std::ostringstream o; o << "ret " << imm; return finish(o.str(), i+2, true); }
    if (op == 0xCB) return finish("retf", i, true);
    if (op == 0xCA && i + 1 < maxLen) { uint16_t imm = p[i] | (p[i+1] << 8); std::ostringstream o; o << "retf " << imm; return finish(o.str(), i+2, true); }
    if (op == 0x90) return finish("nop", i);
    if (op == 0x9C) return finish("pushfq", i);
    if (op == 0x9D) return finish("popfq", i);
    if (op == 0xFF && i < maxLen) {
        unsigned char modrm = p[i++]; unsigned char mod = (modrm >> 6) & 3; unsigned char regop = (modrm >> 3) & 7;
        if (mod == 3) { int reg, rm; if (!ParseRegReg(rex, modrm, reg, rm)) return d;
            if (regop == 4) return finish("jmp "s + kGpr64[rm], i, true);
            if (regop == 2) return finish("call "s + kGpr64[rm], i);
            if (regop == 6) return finish("push "s + kGpr64[rm], i);
        }
    }
    auto regreg = [&](const char* mnem)->DecodedInstr{
        if (i >= maxLen) return d; unsigned char modrm=p[i++]; if (((modrm>>6)&3)!=3) return d;
        int reg,rm; if(!ParseRegReg(rex,modrm,reg,rm)) return d; std::ostringstream o; o<<mnem<<" "<<kGpr64[rm]<<", "<<kGpr64[reg]; return finish(o.str(), i);
    };
    switch (op) {
        case 0x89: return regreg("mov");
        case 0x8B: { if (i>=maxLen) break; unsigned char m=p[i++]; if(((m>>6)&3)!=3) break; int reg,rm; if(!ParseRegReg(rex,m,reg,rm)) break; std::ostringstream o; o<<"mov "<<kGpr64[reg]<<", "<<kGpr64[rm]; return finish(o.str(), i); }
        case 0x8D: { if (i>=maxLen) break; unsigned char m=p[i++]; if(((m>>6)&3)!=3) break; int reg,rm; if(!ParseRegReg(rex,m,reg,rm)) break; std::ostringstream o; o<<"lea "<<kGpr64[reg]<<", ["<<kGpr64[rm]<<"]"; return finish(o.str(), i); }
        case 0x31: return regreg("xor");
        case 0x33: { if (i>=maxLen) break; unsigned char m=p[i++]; if(((m>>6)&3)!=3) break; int reg,rm; if(!ParseRegReg(rex,m,reg,rm)) break; std::ostringstream o; o<<"xor "<<kGpr64[reg]<<", "<<kGpr64[rm]; return finish(o.str(), i); }
        case 0x21: return regreg("and");
        case 0x09: return regreg("or");
        case 0x39: return regreg("cmp");
    }
    if (op >= 0xB8 && op <= 0xBF) {
        int reg = op - 0xB8; if (rex & 0x01) reg |= 0x8; if (i + 4 > maxLen) return d;
        uint32_t imm = p[i] | (p[i+1] << 8) | (p[i+2] << 16) | (p[i+3] << 24);
        std::ostringstream o; o << "mov " << kGpr64[reg] << ", 0x" << std::hex << std::uppercase << imm;
        return finish(o.str(), i + 4);
    }
    if (op == 0x0F && i < maxLen) { unsigned char op2 = p[i++]; if (op2==0x05) return finish("syscall", i); }
    return d;
}

static std::string NormalizeGadgetText(const std::string& in)
{
    std::string out; bool space=false;
    for(char c: in){
        if (c==';' || c==',' || std::isspace(static_cast<unsigned char>(c))) { if(!space && !out.empty()) { out.push_back(' '); space=true; } continue; }
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c)))); space=false;
    }
    if (!out.empty() && out.back()==' ') out.pop_back();
    return out;
}

static std::optional<std::string> DescribeGadget(const BYTE* data, size_t len, bool require_ret)
{
    std::vector<std::string> parts; bool sawRet=false; size_t off=0;
    for (int i=0; i<6 && off<len; ++i) {
        auto d = DecodeOne(data+off, len-off);
        if (!d.ok || d.len==0) break;
        parts.push_back(d.text);
        off += d.len;
        if (d.isRet) { sawRet=true; break; }
    }
    if (parts.empty()) return std::nullopt;
    if (require_ret && !sawRet) return std::nullopt;
    std::ostringstream o;
    for (size_t i=0;i<parts.size();++i){ if(i) o<<" ; "; o<<parts[i]; }
    return o.str();
}

std::optional<uint64_t> FindGadgetRva(const ImageMapping& img,
                                      const std::string& gadget_text,
                                      bool require_ret)
{
    if (!img.view || img.size == 0) return std::nullopt;
    const std::string needle = NormalizeGadgetText(gadget_text);
    const size_t maxLook = 12;
    auto ranges = img.exec_ranges;
    if (ranges.empty()) ranges.push_back({0, img.size});
    for (const auto& r : ranges)
    {
        size_t start = r.start;
        size_t end = (std::min)(r.end, img.size);
        if (start >= end) continue;
        for (size_t rva = start; rva + 1 < end; ++rva)
        {
            auto desc = DescribeGadget(img.view + rva, (std::min)(maxLook, end - rva), require_ret);
            if (!desc.has_value()) continue;
            if (NormalizeGadgetText(desc.value()) == needle)
                return static_cast<uint64_t>(rva);
        }
    }
    return std::nullopt;
}

} // namespace symres
