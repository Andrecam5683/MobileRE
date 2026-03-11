import os
import sys
import string
import re
import pefile
from capstone import *
from elftools.elf.elffile import ELFFile
from collections import defaultdict

# --- CONFIG ---
MIN_STRING = 4
GARBAGE_PREFIXES = ("_ZTV", "_ZTI", "_ZTS", "frameworkdata", "property_offsets", "__typeid")

def detect_arch_elf(elf):
    m = elf["e_machine"]
    if m == "EM_ARM": return CS_ARCH_ARM, CS_MODE_ARM
    if m == "EM_AARCH64": return CS_ARCH_ARM64, CS_MODE_ARM
    if m == "EM_X86_64": return CS_ARCH_X86, CS_MODE_64
    if m == "EM_386": return CS_ARCH_X86, CS_MODE_32
    return CS_ARCH_ARM, CS_MODE_ARM

def detect_arch_pe(pe):
    m = pe.FILE_HEADER.Machine
    if m == 0x8664: return CS_ARCH_X86, CS_MODE_64 # AMD64
    if m == 0x014c: return CS_ARCH_X86, CS_MODE_32 # i386
    if m == 0x01c0: return CS_ARCH_ARM, CS_MODE_ARM # ARM
    if m == 0xaa64: return CS_ARCH_ARM64, CS_MODE_ARM # ARM64
    return CS_ARCH_X86, CS_MODE_64

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <binary>")
        return

    binary_path = sys.argv[1]
    root_out = binary_path + "_MobileRE"
    os.makedirs(root_out, exist_ok=True)
    
    print(f"[+] MobileRE: Analyzing {binary_path}...")

    symbols = {}
    imports, exports = [], []
    text_base, code, arch, mode = 0, b"", None, None

    with open(binary_path, "rb") as f:
        header = f.read(2)
        f.seek(0)
        
        
        if header == b'\x7fE':
            print("[*] Detected ELF format")
            elf = ELFFile(f)
            arch, mode = detect_arch_elf(elf)
            text_sec = elf.get_section_by_name(".text")
            if not text_sec:
                print("[-] No .text section found.")
                return
            text_base = text_sec["sh_addr"]
            code = text_sec.data()

            for sec_name in [".dynsym", ".symtab"]:
                sec = elf.get_section_by_name(sec_name)
                if not sec: continue
                for sym in sec.iter_symbols():
                    addr = sym.entry.st_value
                    if arch == CS_ARCH_ARM: addr &= ~1
                    if sym.entry.st_shndx == "SHN_UNDEF":
                        imports.append(sym.name)
                    else:
                        exports.append(sym.name)
                        if text_base <= addr < (text_base + len(code)):
                            if not any(sym.name.startswith(p) for p in GARBAGE_PREFIXES):
                                symbols[addr] = sym.name

        
        elif header == b'MZ':
            print("[*] Detected PE format")
            pe = pefile.PE(binary_path)
            arch, mode = detect_arch_pe(pe)
            
            
            for section in pe.sections:
                if section.Characteristics & 0x20000000: 
                    text_base = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    code = section.get_data()
                    break
            
            # Extract Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        name = imp.name.decode() if imp.name else f"ord_{imp.ordinal}"
                        imports.append(name)
                        symbols[imp.address] = name

            
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    name = exp.name.decode() if exp.name else f"ord_{exp.ordinal}"
                    exports.append(name)
                    addr = pe.OPTIONAL_HEADER.ImageBase + exp.address
                    symbols[addr] = name
        else:
            print("[-] Unsupported file format.")
            return

    
    with open(binary_path, "rb") as f:
        binary_data = f.read()
    found_strings = []
    cur = ""
    for b in binary_data:
        c = chr(b)
        if c in string.printable and c not in "\n\r\t": cur += c
        else:
            if len(cur) >= MIN_STRING: found_strings.append(cur)
            cur = ""
    with open(os.path.join(root_out, "strings.txt"), "w") as f_out:
        f_out.write("\n".join(found_strings))

    with open(os.path.join(root_out, "imports.txt"), "w") as f_i: f_i.write("\n".join(imports))
    with open(os.path.join(root_out, "exports.txt"), "w") as f_e: f_e.write("\n".join(exports))

    
    md = Cs(arch, mode)
    md.detail = True
    if arch == CS_ARCH_ARM: md.mode = CS_MODE_THUMB # Standard for Mobile
    
    instructions = list(md.disasm(code, text_base))
    stack_vars, struct_access, switches, callgraph, xrefs = set(), defaultdict(set), [], [], defaultdict(list)
    
    with open(os.path.join(root_out, "disassembly.asm"), "w") as f_asm:
        for i, ins in enumerate(instructions):
            if ins.address in symbols:
                f_asm.write(f"\n; {symbols[ins.address]}:\n")
            f_asm.write(f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}\n")

            
            if ins.mnemonic in ["bl", "blx", "b", "beq", "bne", "call", "jmp", "je", "jne"]:
                tgt_str = ins.op_str.replace("#", "").split(" ")[0]
                if tgt_str.startswith("0x"):
                    try:
                        tgt_addr = int(tgt_str, 16)
                        xrefs[tgt_addr].append(hex(ins.address))
                        if ins.mnemonic in ["bl", "blx", "call"]:
                            name = symbols.get(tgt_addr, f"sub_{hex(tgt_addr)[2:]}")
                            callgraph.append(f"{hex(ins.address)} -> {name}")
                    except: pass

            
            mem_match = re.search(r"\[(\w+)(?:,\s*#?(-?0x[0-9a-fA-F]+|\d+))?\]", ins.op_str)
            if mem_match:
                reg, offset = mem_match.groups()
                offset = offset if offset else "0"
                if reg.lower() in ["sp", "fp", "r7", "x29", "ebp", "esp", "rbp", "rsp"]:
                    stack_vars.add(f"{symbols.get(ins.address, 'unknown')} -> local_{offset}")
                else:
                    struct_access[reg].add(offset)

    
    with open(os.path.join(root_out, "xrefs.txt"), "w") as f:
        for addr, sources in sorted(xrefs.items()):
            f.write(f"{symbols.get(addr, hex(addr))} referenced by: {', '.join(sources)}\n")
    
    with open(os.path.join(root_out, "callgraph.txt"), "w") as f: f.write("\n".join(callgraph))
    with open(os.path.join(root_out, "stack.txt"), "w") as f: f.write("\n".join(sorted(stack_vars)))
    with open(os.path.join(root_out, "variables.txt"), "w") as f: f.write("\n".join(sorted(stack_vars)))
    with open(os.path.join(root_out, "switches.txt"), "w") as f: f.write("\n".join(switches))
    with open(os.path.join(root_out, "functions.txt"), "w") as f:
        for addr, name in sorted(symbols.items()): f.write(f"{hex(addr)}: {name}\n")
    
    
    lines = ["// Generated by MobileRE", "#include <stdint.h>\n"]
    for ins in instructions:
        if ins.address in symbols:
            if lines and lines[-1] != "}": lines.append("}\n")
            lines.append(f"void {symbols[ins.address]}() {{")
        
        m, op = ins.mnemonic, ins.op_str
        if "mov" in m and "," in op:
            p = op.split(",")
            lines.append(f"    {p[0].strip()} = {p[1].strip()};")
        elif "ldr" in m or ("mov" in m and "[" in op): 
            p = op.split(",")
            lines.append(f"    {p[0].strip()} = *({p[1].strip()});")
        elif m in ["bl", "blx", "call"]:
            tgt = op.replace("#", "")
            lines.append(f"    {symbols.get(int(tgt, 16) if tgt.startswith('0x') else 0, tgt)}();")
        elif "ret" in m or ("pop" in m and ("pc" in op or "rip" in op)):
            lines.append("    return;")
    
    with open(os.path.join(root_out, "pseudocode.c"), "w") as f:
        f.write("\n".join(lines) + "\n}")

    print(f"[+] Success. Results saved in: {root_out}")

if __name__ == "__main__":
    main()

