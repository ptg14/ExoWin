"""
Console reporter for terminal output
"""
from typing import Any, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from exowin.reporters.base import BaseReporter


class ConsoleReporter(BaseReporter):
    """Generate colored console output using Rich"""

    def __init__(self):
        super().__init__()
        self.console = Console()

    def generate(self, analysis_result: Dict[str, Any], output_path: str = None) -> str:
        """Generate console output"""
        # File Information
        self._print_file_info(analysis_result.get("file_info", {}))

        # PE Information
        self._print_pe_info(analysis_result.get("headers", {}))

        # DLL Information (if applicable)
        dll_features = analysis_result.get("dll_features", {})
        if dll_features and dll_features.get("is_dll"):
            self._print_dll_info(dll_features)

        # Suspicious Indicators
        indicators = analysis_result.get("suspicious_indicators", [])
        if indicators:
            self._print_suspicious_indicators(indicators)

        # Sections
        sections = analysis_result.get("sections", {})
        if sections.get("sections"):
            self._print_sections(sections)

        # Suspicious APIs
        imports = analysis_result.get("imports", {})

        # Print imported DLLs summary
        if imports.get("imports"):
            self._print_imports_summary(imports)

        suspicious_apis = imports.get("suspicious_apis", {})
        if suspicious_apis:
            self._print_suspicious_apis(suspicious_apis)

        # Strings
        strings = analysis_result.get("strings", {})
        if strings.get("categorized"):
            self._print_strings(strings)

        # Disassembly
        disasm = analysis_result.get("disasm", {})
        if disasm.get("instructions"):
            self._print_disasm(disasm)

        return "Console output generated"

    def _print_file_info(self, file_info: Dict[str, Any]):
        """Print file information"""
        entropy = file_info.get("entropy", 0)

        # Choose color based on entropy
        if entropy > 7.0:
            entropy_color = "red"
        elif entropy > 6.0:
            entropy_color = "yellow"
        else:
            entropy_color = "green"

        info_text = f"""[bold]Filename:[/bold] {file_info.get("filename", "Unknown")}
    [bold]Size:[/bold] {file_info.get("size", 0):,} bytes
    [bold]MD5:[/bold] {file_info.get("md5", "N/A")}
    [bold]SHA1:[/bold] {file_info.get("sha1", "N/A")}
    [bold]SHA256:[/bold] {file_info.get("sha256", "N/A")}
    [bold]Entropy:[/bold] [{entropy_color}]{entropy}[/{entropy_color}] - {file_info.get("entropy_interpretation", "")}"""

        if file_info.get("imphash"):
            info_text += f"\n[bold]Imphash:[/bold] {file_info.get('imphash')}"
        if file_info.get("ssdeep"):
            info_text += f"\n[bold]SSDeep:[/bold] {file_info.get('ssdeep')}"

        panel = Panel(
            info_text,
            title="File Information",
            border_style="blue",
            box=box.ROUNDED
        )
        self.console.print(panel)
        self.console.print()

    def _print_pe_info(self, headers: Dict[str, Any]):
        """Print PE information"""
        file_header = headers.get("file_header", {})
        opt_header = headers.get("optional_header", {})

        info_text = f"""[bold]Type:[/bold] {headers.get("pe_type", "Unknown")}
[bold]Machine:[/bold] {file_header.get("Machine", "Unknown")}
[bold]Subsystem:[/bold] {opt_header.get("Subsystem", "Unknown")}
[bold]Timestamp:[/bold] {file_header.get("TimeDateStamp", "Unknown")}
[bold]Entry Point:[/bold] {opt_header.get("AddressOfEntryPoint", "N/A")}
[bold]Image Base:[/bold] {opt_header.get("ImageBase", "N/A")}
[bold]Linker:[/bold] {opt_header.get("MajorLinkerVersion", 0)}.{opt_header.get("MinorLinkerVersion", 0)}
[bold]Sections:[/bold] {file_header.get("NumberOfSections", 0)}"""

        # File characteristics
        chars = file_header.get("Characteristics", [])
        if chars:
            info_text += f"\n[bold]Flags:[/bold] {', '.join(chars[:5])}"

        panel = Panel(
            info_text,
            title="PE Information",
            border_style="cyan",
            box=box.ROUNDED
        )
        self.console.print(panel)
        self.console.print()

        # Security features (DllCharacteristics)
        self._print_security_features(opt_header)

    def _print_security_features(self, opt_header: Dict[str, Any]):
        """Print security features from DllCharacteristics"""
        dll_char = opt_header.get("DllCharacteristics", "0x0")

        # Parse hex value
        try:
            if isinstance(dll_char, str):
                char_value = int(dll_char, 16)
            else:
                char_value = int(dll_char)
        except (ValueError, TypeError):
            char_value = 0

        # Define security features
        features = {
            0x0020: ("HIGH_ENTROPY_VA", "ASLR High Entropy", "green"),
            0x0040: ("DYNAMIC_BASE", "ASLR Enabled", "green"),
            0x0080: ("FORCE_INTEGRITY", "Code Integrity", "green"),
            0x0100: ("NX_COMPAT", "DEP Enabled", "green"),
            0x0400: ("NO_SEH", "No SEH", "yellow"),
            0x4000: ("GUARD_CF", "Control Flow Guard", "green"),
        }

        enabled = []
        disabled = []

        for flag, (name, desc, color) in features.items():
            if char_value & flag:
                enabled.append(f"[{color}][+] {desc}[/{color}]")
            else:
                if name in ["DYNAMIC_BASE", "NX_COMPAT", "GUARD_CF"]:
                    disabled.append(f"[red][-] {desc}[/red]")

        if not enabled and not disabled:
            return  # No security info to display

        text_parts = []
        if enabled:
            text_parts.append("  ".join(enabled))
        if disabled:
            text_parts.append("  ".join(disabled))

        text = "\n".join(text_parts) if text_parts else "[dim]No security features[/dim]"

        panel = Panel(
            text,
            title="Security Features",
            border_style="green" if len(enabled) >= 2 else "red",
            box=box.ROUNDED
        )
        self.console.print(panel)
        self.console.print()

    def _print_suspicious_indicators(self, indicators: list):
        """Print suspicious indicators"""
        text = "\n".join([f"WARNING: {ind}" for ind in indicators])

        panel = Panel(
            text,
            title="Suspicious Indicators",
            border_style="red",
            box=box.ROUNDED
        )
        self.console.print(panel)
        self.console.print()

    def _print_sections(self, sections: Dict[str, Any]):
        """Print sections table"""
        table = Table(title="Sections", box=box.ROUNDED)

        table.add_column("Name", style="cyan")
        table.add_column("Virtual Size", justify="right")
        table.add_column("Raw Size", justify="right")
        table.add_column("Entropy", justify="right")
        table.add_column("Characteristics", style="dim")

        for section in sections.get("sections", []):
            entropy = section.get("Entropy", 0)

            # Color entropy based on value
            if entropy > 7.0:
                entropy_str = f"[red]{entropy}[/red]"
            elif entropy > 6.0:
                entropy_str = f"[yellow]{entropy}[/yellow]"
            else:
                entropy_str = f"[green]{entropy}[/green]"

            chars = ", ".join(section.get("Characteristics", []))[:40]

            table.add_row(
                section.get("Name", ""),
                f"{section.get('VirtualSize', 0):,}",
                f"{section.get('RawSize', 0):,}",
                entropy_str,
                chars
            )

        self.console.print(table)
        self.console.print()

    def _print_imports_summary(self, imports: Dict[str, Any]):
        """Print imported DLLs summary"""
        import_list = imports.get("imports", [])
        if not import_list:
            return

        # Count total functions
        total_functions = sum(len(imp.get("functions", [])) for imp in import_list)
        dll_names = [imp.get("dll", "") for imp in import_list]

        # Create summary
        summary = f"[bold]Total:[/bold] {len(dll_names)} DLLs, {total_functions} functions\n"
        summary += f"[bold]DLLs:[/bold] {', '.join(dll_names[:15])}"
        if len(dll_names) > 15:
            summary += f" [dim](+{len(dll_names) - 15} more)[/dim]"

        panel = Panel(
            summary,
            title="Imports",
            border_style="blue",
            box=box.ROUNDED
        )
        self.console.print(panel)
        self.console.print()

    def _print_suspicious_apis(self, suspicious_apis: Dict[str, list]):
        """Print suspicious APIs"""
        for category, apis in suspicious_apis.items():
            title = category.replace('_', ' ').title()
            api_list = ", ".join(apis[:10])

            panel = Panel(
                api_list,
                title=f"{title}",
                border_style="yellow",
                box=box.ROUNDED
            )
            self.console.print(panel)

        self.console.print()

    def _print_strings(self, strings: Dict[str, Any]):
        """Print strings analysis"""
        categorized = strings.get("categorized", {})

        if categorized.get("urls"):
            urls = "\n".join(categorized["urls"][:10])
            panel = Panel(
                urls,
                title=f"URLs ({len(categorized['urls'])} found)",
                border_style="blue",
                box=box.ROUNDED
            )
            self.console.print(panel)

        if categorized.get("ip_addresses"):
            ips = "\n".join(categorized["ip_addresses"][:10])
            panel = Panel(
                ips,
                title=f"IP Addresses ({len(categorized['ip_addresses'])} found)",
                border_style="cyan",
                box=box.ROUNDED
            )
            self.console.print(panel)

        if categorized.get("suspicious_keywords"):
            keywords = ", ".join(categorized["suspicious_keywords"][:20])
            panel = Panel(
                keywords,
                title="Suspicious Keywords",
                border_style="red",
                box=box.ROUNDED
            )
            self.console.print(panel)

        self.console.print()

    def _print_dll_info(self, dll_features: Dict[str, Any]):
        """Print DLL-specific information"""
        dll_info = dll_features.get("dll_info", {})
        dll_type = dll_features.get("dll_type_analysis", {})
        dll_chars = dll_features.get("dll_characteristics", {})
        exports = dll_features.get("exports", {})

        # Security features
        security = dll_chars.get("security_features", {})
        security_score = dll_chars.get("security_score", 0)

        # Choose color based on security score
        if security_score >= 75:
            score_color = "green"
        elif security_score >= 50:
            score_color = "yellow"
        else:
            score_color = "red"

        # Security features text
        security_items = []
        if security.get("aslr_enabled"):
            security_items.append("[green]ASLR[/green]")
        else:
            security_items.append("[red]No ASLR[/red]")
        if security.get("dep_enabled"):
            security_items.append("[green]DEP[/green]")
        else:
            security_items.append("[red]No DEP[/red]")
        if security.get("cfg_enabled"):
            security_items.append("[green]CFG[/green]")
        else:
            security_items.append("[dim]No CFG[/dim]")

        info_text = f"""[bold]DLL Type:[/bold] {dll_type.get("type", "Unknown")}
[bold]Subtypes:[/bold] {", ".join(dll_type.get("subtypes", [])) or "None"}
[bold]Export Count:[/bold] {exports.get("count", 0)} ({exports.get("named_count", 0)} named, {exports.get("ordinal_only_count", 0)} ordinal-only)
[bold]Forwarded Exports:[/bold] {len(dll_features.get("forwarded_functions", []))}
[bold]Security Score:[/bold] [{score_color}]{security_score}/100[/{score_color}]
[bold]Security Features:[/bold] {" | ".join(security_items)}"""

        # Risk level
        risk_level = dll_info.get("risk_level", "NONE")
        if risk_level == "HIGH":
            risk_color = "red"
        elif risk_level == "MEDIUM":
            risk_color = "yellow"
        elif risk_level == "LOW":
            risk_color = "cyan"
        else:
            risk_color = "green"

        info_text += f"\n[bold]Risk Level:[/bold] [{risk_color}]{risk_level}[/{risk_color}]"

        panel = Panel(
            info_text,
            title="DLL Analysis",
            border_style="magenta",
            box=box.ROUNDED
        )
        self.console.print(panel)

        # Print suspicious exports if any
        suspicious_exports = exports.get("categories", {}).get("suspicious", [])
        if suspicious_exports:
            exports_text = ", ".join(suspicious_exports[:10])
            panel = Panel(
                exports_text,
                title=f"Suspicious Exports ({len(suspicious_exports)} found)",
                border_style="red",
                box=box.ROUNDED
            )
            self.console.print(panel)

        # Print DLL indicators
        dll_indicators = dll_features.get("suspicious_indicators", [])
        if dll_indicators:
            indicator_lines = []
            for ind in dll_indicators:
                severity = ind.get("severity", "info").upper()
                desc = ind.get("description", "")
                if severity == "HIGH":
                    indicator_lines.append(f"[red][{severity}][/red] {desc}")
                elif severity == "MEDIUM":
                    indicator_lines.append(f"[yellow][{severity}][/yellow] {desc}")
                else:
                    indicator_lines.append(f"[dim][{severity}][/dim] {desc}")

            panel = Panel(
                "\n".join(indicator_lines),
                title="DLL Suspicious Indicators",
                border_style="yellow",
                box=box.ROUNDED
            )
            self.console.print(panel)

        self.console.print()

    def _print_disasm(self, disasm: Dict[str, Any]):
        """Print suspicious disassembly patterns only, grouping repeated instructions"""
        suspicious_instructions = disasm.get("suspicious", [])
        total_instructions = disasm.get("total_instructions", 0)
        entry_point = disasm.get("entry_point", "Unknown")

        # Print results
        if not suspicious_instructions:
            panel = Panel(
                f"[green]No suspicious patterns detected in {total_instructions:,} instructions[/green]",
                title=f"Disassembly Analysis (EP: {entry_point})",
                border_style="green",
                box=box.ROUNDED
            )
            self.console.print(panel)
            self.console.print()
            return

        # Group consecutive repeated instructions
        grouped = []
        i = 0
        while i < len(suspicious_instructions):
            current = suspicious_instructions[i]
            current_key = (current.get("section"), current.get("mnemonic"), current.get("bytes"), current.get("reason"))

            # Find consecutive same instructions
            start_addr = current.get("address", "")
            count = 1
            j = i + 1

            while j < len(suspicious_instructions):
                next_instr = suspicious_instructions[j]
                next_key = (next_instr.get("section"), next_instr.get("mnemonic"), next_instr.get("bytes"), next_instr.get("reason"))
                if next_key == current_key:
                    count += 1
                    j += 1
                else:
                    break

            end_addr = suspicious_instructions[j-1].get("address", "") if count > 1 else None

            grouped.append({
                "section": current.get("section", ""),
                "start_addr": start_addr,
                "end_addr": end_addr,
                "count": count,
                "bytes": current.get("bytes", ""),
                "mnemonic": current.get("mnemonic", ""),
                "operands": current.get("operands", ""),
                "reason": current.get("reason", "")
            })

            i = j

        # Create table for suspicious instructions
        table = Table(
            title=f"Suspicious Disassembly (EP: {entry_point}, {len(suspicious_instructions)} suspicious in {total_instructions:,} instructions)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold red"
        )

        table.add_column("Section", style="cyan")
        table.add_column("Address", style="green", justify="right")
        table.add_column("Bytes", style="dim")
        table.add_column("Instruction", style="yellow")
        table.add_column("Reason", style="red")

        for item in grouped:
            section = item["section"]
            if item["count"] > 1:
                address = f"{item['start_addr']} - {item['end_addr']} (x{item['count']})"
            else:
                address = item["start_addr"]

            bytes_str = item["bytes"]
            instruction_str = f"{item['mnemonic']} {item['operands']}".strip()
            reason = item["reason"]

            table.add_row(section, address, bytes_str, instruction_str, reason)

        self.console.print(table)
        self.console.print()
