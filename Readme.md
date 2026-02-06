NTKernelWalkerLib is a self contained library for resolving kernel offsets from user mode. It wraps dbghelp to fetch RVAs of exported symbols from ntoskrnl.exe and adds a lightweight image mapper that can scan executable sections to find short ROP gadgets such as “pop rcx ; ret” or “jmp rax”. The library exposes two main groups of functions:

Symbol resolution via PDB/exports:
symres::ResolveNtoskrnlSymbolRva(const std::string& name, const std::wstring& symPath=L"") looks up an export in the running kernel by loading the on-disk ntoskrnl with dbghelp and returns its RVA.
symres::ResolveSymbolRvaFromFile(const std::wstring& imagePath, const std::string& name, const std::wstring& symPath=L"") does the same for any PE you point it at (e.g., a specific ntoskrnl build).

Image mapping and gadget search:
symres::MapImageFile(const std::wstring& path, ImageMapping& out) maps a PE with SEC_IMAGE and records executable section ranges.
symres::FindGadgetRva(const ImageMapping& img, const std::string& gadgetText, bool requireRet=true) scans those ranges for a gadget whose normalized text matches gadgetText (e.g., “pop rax ; ret”). It returns the RVA of the first match.
symres::UnmapImageFile(ImageMapping& img) cleans up the mapping.

A typical flow: map ntoskrnl.exe, call FindGadgetRva for the pop/jmp gadgets you need, call ResolveSymbolRvaFromFile for functions like KiApcInterrupt or memcpy, then unmap. All return RVAs, so add the running ntoskrnl base to get VAs. No network is required if symbols are already cached; otherwise the default symbol path is srv*%SystemRoot%\Symbols*https://msdl.microsoft.com/download/symbols.
