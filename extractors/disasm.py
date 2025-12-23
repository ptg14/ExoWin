"""
Disassembly extractor
"""
from typing import Any, Dict, List
import pefile

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from exowin.extractors.base import BaseExtractor


class DisasmExtractor(BaseExtractor):
    """Disassemble all executable sections and find suspicious patterns"""

    # Suspicious patterns to detect
    SUSPICIOUS_MNEMONICS = {
        # Anti-debugging / timing
        "rdtsc", "rdtscp", "cpuid", "int", "int3",
        # VM detection
        "sidt", "sgdt", "sldt", "smsw", "str", "in", "out",
        # System calls (direct syscall = evasion)
        "syscall", "sysenter", "int2e",
        # Self-modifying code / shellcode
        "stosb", "stosw", "stosd", "stosq",
        "movsb", "movsw", "movsd", "movsq",
        "lodsb", "lodsw", "lodsd", "lodsq",
        "scasb", "scasw", "scasd", "scasq",
        # Obfuscation / encryption
        "xor", "ror", "rol", "rcl", "rcr",
        # Privilege / kernel access
        "cli", "sti", "hlt", "lidt", "lgdt",
        # Hardware breakpoint manipulation
        "mov dr", "mov cr",
        # Indirect execution (ROP/JOP gadgets)
        "jmp", "call",
    }

    SUSPICIOUS_OPERAND_PATTERNS = [
        # Anti-debugging API calls
        "isdebuggerpresent", "checkremotedebuggerpr", "ntqueryinformationpr",
        "outputdebugstring", "gettickcount", "queryperformancecoun",
        # Process injection
        "virtualalloc", "virtualallocex", "virtualprotect", "writeprocessmemory",
        "createremotethread", "ntcreatethreadex", "rtlcreateuser",
        # Shellcode execution
        "shellexecute", "winexec", "createprocess", "system",
        # Network
        "wsastartup", "socket", "connect", "send", "recv", "internetopen",
        # Registry
        "regsetvalue", "regcreatekey", "regopenkey",
        # File operations
        "deletefile", "createfile", "writefile",
        # Crypto
        "cryptencrypt", "cryptdecrypt",
    ]

    def extract(self, pe: pefile.PE, filepath: str = None, num_instructions: int = None) -> Dict[str, Any]:
        """Disassemble all executable sections and find suspicious instructions"""
        if not CAPSTONE_AVAILABLE:
            return {
                "error": "Capstone not available. Install with: pip install capstone",
                "instructions": [],
                "suspicious": []
            }

        try:
            # Get entry point
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

            # Determine architecture
            if pe.FILE_HEADER.Machine == 0x14c:  # IMAGE_FILE_MACHINE_I386
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                return {
                    "error": f"Unsupported architecture: 0x{pe.FILE_HEADER.Machine:x}",
                    "instructions": [],
                    "suspicious": []
                }

            # Scan all executable sections
            all_instructions = []
            suspicious_instructions = []

            for section in pe.sections:
                # Check if section is executable
                characteristics = section.Characteristics
                is_executable = bool(characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE

                if not is_executable:
                    continue

                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_rva = section.VirtualAddress
                section_data = section.get_data()

                # Disassemble section
                for insn in md.disasm(section_data, section_rva):
                    instr_data = {
                        "address": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "operands": insn.op_str,
                        "bytes": insn.bytes.hex(),
                        "size": insn.size,
                        "section": section_name,
                    }

                    # Check if suspicious
                    is_sus, reason = self._is_suspicious(insn)
                    if is_sus:
                        instr_data["reason"] = reason
                        suspicious_instructions.append(instr_data)

                    all_instructions.append(instr_data)

            # Group suspicious instructions to reduce JSON size
            grouped_suspicious = self._group_suspicious(suspicious_instructions)

            return {
                "entry_point": hex(entry_point),
                "total_instructions": len(all_instructions),
                "suspicious_count": len(suspicious_instructions),
                "instructions": all_instructions,
                "suspicious": suspicious_instructions,  # Full list for HTML expandable
                "suspicious_grouped": grouped_suspicious,  # Compact for JSON
            }

        except Exception as e:
            return {
                "error": f"Failed to disassemble: {str(e)}",
                "instructions": [],
                "suspicious": []
            }

    def _is_suspicious(self, insn) -> tuple:
        """Check if instruction is suspicious, return (is_suspicious, reason)"""
        mnemonic = insn.mnemonic.lower()
        operands = insn.op_str.lower()

        # Check mnemonic
        # Anti-debug timing
        if mnemonic in ["rdtsc", "rdtscp"]:
            return True, "Anti-debug timing"

        # CPUID - VM detection
        if mnemonic == "cpuid":
            return True, "VM/CPU detection"

        # INT instructions
        if mnemonic in ["int", "int3"]:
            if "3" in operands or mnemonic == "int3":
                return True, "Debugger trap (INT3)"
            elif "0x2e" in operands or "2eh" in operands:
                return True, "Syscall via INT 2E"
            elif "0x80" in operands or "80h" in operands:
                return True, "Linux syscall INT 0x80"

        # VM detection instructions
        if mnemonic in ["sidt", "sgdt", "sldt", "smsw", "str"]:
            return True, "VM detection"

        # I/O port access - VM detection or hardware access
        if mnemonic == "in":
            return True, "I/O port read (VM detect)"
        if mnemonic == "out":
            return True, "I/O port write"

        # Direct syscall (evasion technique)
        if mnemonic == "syscall":
            return True, "Direct syscall (evasion)"
        if mnemonic == "sysenter":
            return True, "Direct sysenter (evasion)"

        # String operations - shellcode patterns
        if mnemonic in ["stosb", "stosw", "stosd", "stosq"]:
            return True, "Memory fill (shellcode)"
        if mnemonic in ["movsb", "movsw", "movsd", "movsq"]:
            return True, "Memory copy (shellcode)"
        if mnemonic in ["lodsb", "lodsw", "lodsd", "lodsq"]:
            return True, "String load (shellcode)"
        if mnemonic in ["scasb", "scasw", "scasd", "scasq"]:
            return True, "String scan (shellcode)"

        # Obfuscation / encryption
        if mnemonic in ["xor", "ror", "rol", "rcl", "rcr"]:
            parts = operands.replace(" ", "").split(",")
            # XOR with same register = zeroing (common), skip
            if len(parts) == 2 and parts[0] == parts[1] and mnemonic == "xor":
                return False, ""
            if mnemonic in ["ror", "rol", "rcl", "rcr"]:
                return True, "Obfuscation/Encryption"

        # Privilege instructions
        if mnemonic == "cli":
            return True, "Disable interrupts"
        if mnemonic == "sti":
            return True, "Enable interrupts"
        if mnemonic == "hlt":
            return True, "Halt CPU"
        if mnemonic in ["lidt", "lgdt"]:
            return True, "Load IDT/GDT (rootkit)"

        # Debug register access
        if mnemonic == "mov" and ("dr" in operands or "cr" in operands):
            if "dr" in operands:
                return True, "Debug register access"
            if "cr" in operands:
                return True, "Control register access"

        # Check for suspicious API calls
        if mnemonic == "call":
            for pattern in self.SUSPICIOUS_OPERAND_PATTERNS:
                if pattern in operands:
                    return True, f"Suspicious API: {pattern}"

        # Check for PEB/TEB access (anti-debug)
        if "fs:" in operands or "gs:" in operands:
            if "0x30" in operands or "30h" in operands or "[0x30]" in operands:
                return True, "PEB access (anti-debug)"
            elif "0x60" in operands or "60h" in operands:
                return True, "PEB access (64-bit)"
            elif "0x18" in operands or "18h" in operands:
                return True, "TEB access"

        return False, ""

    def _group_suspicious(self, suspicious_list: list) -> list:
        """Group consecutive identical suspicious instructions to reduce size"""
        if not suspicious_list:
            return []

        grouped = []
        i = 0
        while i < len(suspicious_list):
            current = suspicious_list[i]
            current_key = (
                current.get("section"),
                current.get("mnemonic"),
                current.get("bytes"),
                current.get("reason")
            )

            addresses = [current.get("address")]
            j = i + 1

            while j < len(suspicious_list):
                next_instr = suspicious_list[j]
                next_key = (
                    next_instr.get("section"),
                    next_instr.get("mnemonic"),
                    next_instr.get("bytes"),
                    next_instr.get("reason")
                )
                if next_key == current_key:
                    addresses.append(next_instr.get("address"))
                    j += 1
                else:
                    break

            grouped.append({
                "section": current.get("section"),
                "addresses": addresses,
                "count": len(addresses),
                "mnemonic": current.get("mnemonic"),
                "operands": current.get("operands"),
                "bytes": current.get("bytes"),
                "reason": current.get("reason"),
            })
            i = j

        return grouped
