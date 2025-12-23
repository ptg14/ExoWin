"""
HTML reporter - Detailed version matching JSON output
"""
from pathlib import Path
from typing import Any, Dict, List, Optional
import datetime
import html as html_escape

from exowin.reporters.base import BaseReporter


class HTMLReporter(BaseReporter):
    """Generate detailed HTML reports"""

    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Report - {filename}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .header p {{
            opacity: 0.9;
        }}
        .toc {{
            padding: 20px 30px;
        }}
        .toc h3 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        .toc ul {{
            list-style: none;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .toc ul li a {{
            color: #667eea;
            text-decoration: none;
            padding: 8px 18px;
            background: #f0f2ff;
            border-radius: 25px;
            border: none;
            transition: all 0.3s;
            font-weight: 500;
        }}
        .toc ul li a:hover {{
            background: #667eea;
            color: white;
        }}
        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 30px;
            padding: 20px;
            border-radius: 8px;
            background: #f8f9fa;
        }}
        .section h2 {{
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.5em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        .section h3 {{
            color: #555;
            margin: 15px 0 10px 0;
            font-size: 1.2em;
        }}
        .section h4 {{
            color: #667eea;
            margin: 10px 0 8px 0;
            font-size: 1em;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }}
        .info-item {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        .info-item strong {{
            display: block;
            color: #667eea;
            margin-bottom: 5px;
        }}
        .info-item code {{
            background: #f1f3f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }}
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .danger {{
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .success {{
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .info {{
            background: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            border-radius: 5px;
            overflow: hidden;
        }}
        th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-size: 0.9em;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
            font-size: 0.85em;
        }}
        td code {{
            background: #f1f3f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .badge-danger {{
            background: #dc3545;
            color: white;
        }}
        .badge-warning {{
            background: #ffc107;
            color: #333;
        }}
        .badge-success {{
            background: #28a745;
            color: white;
        }}
        .badge-info {{
            background: #17a2b8;
            color: white;
        }}
        .badge-secondary {{
            background: #6c757d;
            color: white;
        }}
        ul {{
            list-style: none;
            padding: 0;
        }}
        ul li {{
            padding: 8px;
            margin: 5px 0;
            background: white;
            border-left: 3px solid #667eea;
            border-radius: 3px;
        }}
        .collapsible {{
            background: #667eea;
            color: white;
            cursor: pointer;
            padding: 12px 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 1em;
            border-radius: 5px;
            margin-top: 10px;
            transition: 0.3s;
        }}
        .collapsible:hover {{
            background: #5a6fd6;
        }}
        .collapsible:after {{
            content: '+';
            float: right;
            font-weight: bold;
        }}
        .collapsible.active:after {{
            content: '-';
        }}
        .collapsible-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background: white;
            border-radius: 0 0 5px 5px;
        }}
        .collapsible-content.show {{
            max-height: none;
        }}
        .strings-list {{
            max-height: 400px;
            overflow-y: auto;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .dll-section {{
            margin: 15px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }}
        .dll-header {{
            background: #f8f9fa;
            padding: 10px 15px;
            font-weight: bold;
            color: #667eea;
            border-bottom: 1px solid #ddd;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
        }}
        .stat-item {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border: 1px solid #ddd;
        }}
        .stat-item .number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-item .label {{
            font-size: 0.85em;
            color: #666;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Malware Analysis Report</h1>
            <p>{filename}</p>
            <p>Generated: {timestamp}</p>
        </div>

        <div class="toc">
            <h3>📋 Quick Navigation</h3>
            <ul>
                <li><a href="#file-info">File Info</a></li>
                <li><a href="#indicators">Indicators</a></li>
                <li><a href="#dll-features">DLL Analysis</a></li>
                <li><a href="#pe-headers">PE Headers</a></li>
                <li><a href="#sections">Sections</a></li>
                <li><a href="#imports">Imports</a></li>
                <li><a href="#exports">Exports</a></li>
                <li><a href="#strings">Strings</a></li>
                <li><a href="#disasm">Disassembly</a></li>
            </ul>
        </div>

        <div class="content">
            {file_info_section}
            {suspicious_section}
            {dll_section}
            {pe_headers_section}
            {sections_section}
            {imports_section}
            {exports_section}
            {strings_section}
            {disasm_section}
        </div>

        <div class="footer">
            <p>Generated by ExoWin v1.1.0</p>
        </div>
    </div>

    <script>
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {{
            coll[i].addEventListener("click", function() {{
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                content.classList.toggle("show");
            }});
        }}
    </script>
</body>
</html>
"""

    def generate(self, analysis_result: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Generate detailed HTML report"""
        file_info = analysis_result.get("file_info", {})
        headers = analysis_result.get("headers", {})
        imports = analysis_result.get("imports", {})

        # Build all sections
        file_info_section = self._build_file_info(file_info)
        suspicious_section = self._build_suspicious_indicators(analysis_result.get("suspicious_indicators", []))
        dll_section = self._build_dll_section(analysis_result.get("dll_features", {}))
        pe_headers_section = self._build_pe_headers(headers)
        sections_section = self._build_sections(analysis_result.get("sections", {}))
        imports_section = self._build_imports(imports)
        exports_section = self._build_exports(imports.get("exports", {}))
        strings_section = self._build_strings(analysis_result.get("strings", {}))
        disasm_section = self._build_disasm(analysis_result.get("disasm", {}))

        # Generate HTML
        html = self.HTML_TEMPLATE.format(
            filename=file_info.get("filename", "Unknown"),
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            file_info_section=file_info_section,
            suspicious_section=suspicious_section,
            dll_section=dll_section,
            pe_headers_section=pe_headers_section,
            sections_section=sections_section,
            imports_section=imports_section,
            exports_section=exports_section,
            strings_section=strings_section,
            disasm_section=disasm_section,
        )

        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)

        return html

    def _escape(self, text: str) -> str:
        """Escape HTML special characters"""
        if text is None:
            return "N/A"
        return html_escape.escape(str(text))

    def _build_file_info(self, file_info: Dict[str, Any]) -> str:
        """Build detailed file information section"""
        entropy = file_info.get("entropy", 0)
        entropy_class = "danger" if entropy > 7.0 else "warning" if entropy > 6.0 else "success"

        return f"""
        <div class="section" id="file-info">
            <h2>📄 File Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Filename</strong>
                    {self._escape(file_info.get("filename", "Unknown"))}
                </div>
                <div class="info-item">
                    <strong>File Path</strong>
                    <code>{self._escape(file_info.get("filepath", "N/A"))}</code>
                </div>
                <div class="info-item">
                    <strong>Size</strong>
                    {file_info.get("size", 0):,} bytes
                </div>
                <div class="info-item">
                    <strong>MD5</strong>
                    <code>{self._escape(file_info.get("md5", "N/A"))}</code>
                </div>
                <div class="info-item">
                    <strong>SHA1</strong>
                    <code>{self._escape(file_info.get("sha1", "N/A"))}</code>
                </div>
                <div class="info-item">
                    <strong>SHA256</strong>
                    <code>{self._escape(file_info.get("sha256", "N/A"))}</code>
                </div>
                <div class="info-item">
                    <strong>Imphash</strong>
                    <code>{self._escape(file_info.get("imphash", "N/A"))}</code>
                </div>
                <div class="info-item">
                    <strong>SSDeep</strong>
                    <code>{self._escape(file_info.get("ssdeep", "N/A"))}</code>
                </div>
            </div>
            <div class="{entropy_class}" style="margin-top: 15px;">
                <strong>Entropy: {entropy}</strong><br>
                {self._escape(file_info.get("entropy_interpretation", ""))}
            </div>
        </div>
        """

    def _build_suspicious_indicators(self, indicators: list) -> str:
        """Build suspicious indicators section"""
        if not indicators:
            return f"""
            <div class="section" id="indicators">
                <h2>⚠️ Suspicious Indicators</h2>
                <div class="success">
                    <strong>✅ No suspicious indicators detected</strong>
                </div>
            </div>
            """

        items = "\n".join([f"<li>⚠️ {self._escape(ind)}</li>" for ind in indicators])

        return f"""
        <div class="section" id="indicators">
            <h2>⚠️ Suspicious Indicators</h2>
            <div class="danger">
                <ul>
                    {items}
                </ul>
            </div>
        </div>
        """

    def _build_dll_section(self, dll_features: Dict[str, Any]) -> str:
        """Build DLL-specific analysis section"""
        if not dll_features:
            return ""

        dll_info = dll_features.get("dll_info", {})
        dll_type = dll_features.get("dll_type_analysis", {})
        dll_chars = dll_features.get("dll_characteristics", {})
        export_info = dll_features.get("exports", {})
        security = dll_chars.get("security_features", {})
        security_score = dll_chars.get("security_score", 0)

        # Security score styling
        if security_score >= 75:
            score_class = "success"
            score_badge = "badge-success"
        elif security_score >= 50:
            score_class = "warning"
            score_badge = "badge-warning"
        else:
            score_class = "danger"
            score_badge = "badge-danger"

        # Security features
        security_html = []
        for feat, label in [("aslr_enabled", "ASLR"), ("dep_enabled", "DEP"), ("cfg_enabled", "CFG"), ("high_entropy_va", "High Entropy VA")]:
            if security.get(feat):
                security_html.append(f'<span class="badge badge-success">✓ {label}</span>')
            else:
                security_html.append(f'<span class="badge badge-danger">✗ {label}</span>')

        content = f"""
        <div class="section" id="dll-features">
            <h2>📦 DLL Analysis</h2>

            <div class="stats-grid">
                <div class="stat-item">
                    <div class="number">{export_info.get("count", 0)}</div>
                    <div class="label">Exports</div>
                </div>
                <div class="stat-item">
                    <div class="number">{export_info.get("named_count", 0)}</div>
                    <div class="label">Named Exports</div>
                </div>
                <div class="stat-item">
                    <div class="number">{len(dll_features.get("forwarded_functions", []))}</div>
                    <div class="label">Forwarded</div>
                </div>
                <div class="stat-item">
                    <div class="number" style="color: {'#28a745' if security_score >= 75 else '#ffc107' if security_score >= 50 else '#dc3545'};">{security_score}/100</div>
                    <div class="label">Security Score</div>
                </div>
            </div>

            <div class="info-grid">
                <div class="info-item">
                    <strong>DLL Type</strong>
                    <span class="badge badge-info">{self._escape(dll_type.get("type", "Unknown"))}</span>
                </div>
                <div class="info-item">
                    <strong>Subtypes</strong>
                    {", ".join(dll_type.get("subtypes", [])) or "None"}
                </div>
                <div class="info-item">
                    <strong>Risk Level</strong>
                    <span class="badge {'badge-danger' if dll_info.get('risk_level') == 'HIGH' else 'badge-warning' if dll_info.get('risk_level') == 'MEDIUM' else 'badge-success'}">{self._escape(dll_info.get("risk_level", "NONE"))}</span>
                </div>
            </div>

            <h3>Security Features</h3>
            <div class="info-item">
                {" ".join(security_html)}
            </div>
        """

        # Export categories
        categories = export_info.get("categories", {})
        if any(categories.values()):
            content += """
            <h3>Export Categories</h3>
            <div class="info-grid">
            """
            for cat_name, cat_funcs in categories.items():
                if cat_funcs:
                    content += f"""
                    <div class="info-item">
                        <strong>{self._escape(cat_name.replace('_', ' ').title())}</strong>
                        {len(cat_funcs)} functions
                    </div>
                    """
            content += "</div>"

        # Suspicious export indicators
        indicators = dll_features.get("suspicious_indicators", [])
        if indicators:
            content += """
            <h3>DLL Suspicious Indicators</h3>
            <div class="danger">
                <ul>
            """
            for ind in indicators:
                severity = ind.get("severity", "info").upper()
                desc = ind.get("description", "")
                badge_class = "badge-danger" if severity == "HIGH" else "badge-warning" if severity == "MEDIUM" else "badge-secondary"
                content += f'<li><span class="badge {badge_class}">{severity}</span> {self._escape(desc)}</li>'
            content += """
                </ul>
            </div>
            """

        # Export functions table
        export_funcs = export_info.get("functions", [])
        if export_funcs:
            content += f"""
            <button class="collapsible">📋 View All Exports ({len(export_funcs)} functions)</button>
            <div class="collapsible-content">
                <table>
                    <thead>
                        <tr><th>Ordinal</th><th>Name</th><th>Address</th><th>Forwarded To</th></tr>
                    </thead>
                    <tbody>
            """
            for exp in export_funcs[:200]:  # Limit display
                content += f"""
                    <tr>
                        <td>{exp.get("ordinal", "")}</td>
                        <td><code>{self._escape(exp.get("name", "(ordinal only)"))}</code></td>
                        <td><code>{self._escape(exp.get("address", ""))}</code></td>
                        <td>{self._escape(exp.get("forwarder", "")) if exp.get("is_forwarded") else ""}</td>
                    </tr>
                """
            content += """
                    </tbody>
                </table>
            </div>
            """

        # Forwarded functions
        forwarded = dll_features.get("forwarded_functions", [])
        if forwarded:
            content += f"""
            <h3>Forwarded Functions ({len(forwarded)})</h3>
            <table>
                <thead>
                    <tr><th>Export Name</th><th>Target DLL</th><th>Target Function</th></tr>
                </thead>
                <tbody>
            """
            for fwd in forwarded:
                content += f"""
                    <tr>
                        <td><code>{self._escape(fwd.get("export_name", ""))}</code></td>
                        <td><span class="badge badge-info">{self._escape(fwd.get("target_dll", ""))}</span></td>
                        <td><code>{self._escape(fwd.get("target_function", ""))}</code></td>
                    </tr>
                """
            content += """
                </tbody>
            </table>
            """

        content += "</div>"
        return content

    def _build_pe_headers(self, headers: Dict[str, Any]) -> str:
        """Build detailed PE headers section"""
        content = f"""
        <div class="section" id="pe-headers">
            <h2>🔧 PE Headers</h2>
            <div class="info-item" style="margin-bottom: 15px;">
                <strong>PE Type</strong>
                <span class="badge badge-info">{self._escape(headers.get("pe_type", "Unknown"))}</span>
            </div>
        """

        # DOS Header
        dos_header = headers.get("dos_header", {})
        if dos_header:
            content += """
            <h3>DOS Header</h3>
            <table>
                <thead>
                    <tr><th>Field</th><th>Value</th></tr>
                </thead>
                <tbody>
            """
            for key, value in dos_header.items():
                content += f"<tr><td><strong>{self._escape(key)}</strong></td><td><code>{self._escape(value)}</code></td></tr>"
            content += "</tbody></table>"

        # File Header (COFF)
        file_header = headers.get("file_header", {})
        if file_header:
            content += """
            <h3>File Header (COFF)</h3>
            <table>
                <thead>
                    <tr><th>Field</th><th>Value</th></tr>
                </thead>
                <tbody>
            """
            for key, value in file_header.items():
                if key == "Characteristics":
                    chars = ", ".join(value) if isinstance(value, list) else value
                    content += f"<tr><td><strong>{self._escape(key)}</strong></td><td>{self._escape(chars)}</td></tr>"
                else:
                    content += f"<tr><td><strong>{self._escape(key)}</strong></td><td><code>{self._escape(value)}</code></td></tr>"
            content += "</tbody></table>"

        # Optional Header
        opt_header = headers.get("optional_header", {})
        if opt_header:
            content += """
            <h3>Optional Header</h3>
            <table>
                <thead>
                    <tr><th>Field</th><th>Value</th></tr>
                </thead>
                <tbody>
            """
            for key, value in opt_header.items():
                content += f"<tr><td><strong>{self._escape(key)}</strong></td><td><code>{self._escape(value)}</code></td></tr>"
            content += "</tbody></table>"

        # Warnings
        warnings = headers.get("warnings", [])
        if warnings:
            items = "\n".join([f"<li>{self._escape(w)}</li>" for w in warnings])
            content += f"""
            <h3>⚡ PE Parsing Warnings</h3>
            <div class="warning">
                <ul>{items}</ul>
            </div>
            """

        content += "</div>"
        return content

    def _build_sections(self, sections: Dict[str, Any]) -> str:
        """Build detailed sections table"""
        sections_list = sections.get("sections", [])
        count = sections.get("count", len(sections_list))

        content = f"""
        <div class="section" id="sections">
            <h2>📦 Sections</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="number">{count}</div>
                    <div class="label">Total Sections</div>
                </div>
            </div>
        """

        if sections_list:
            content += """
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Virtual Address</th>
                        <th>Virtual Size</th>
                        <th>Raw Size</th>
                        <th>Entropy</th>
                        <th>MD5</th>
                        <th>Characteristics</th>
                    </tr>
                </thead>
                <tbody>
            """

            for section in sections_list:
                entropy = section.get("Entropy", 0)
                entropy_badge = "danger" if entropy > 7.0 else "warning" if entropy > 6.0 else "success"
                chars = ", ".join(section.get("Characteristics", []))
                suspicious = section.get("suspicious", [])
                suspicious_html = f' <span class="badge badge-danger">⚠️ {", ".join(suspicious)}</span>' if suspicious else ""

                content += f"""
                <tr>
                    <td><strong>{self._escape(section.get("Name", ""))}</strong>{suspicious_html}</td>
                    <td><code>{self._escape(section.get("VirtualAddress", "0x0"))}</code></td>
                    <td>{section.get("VirtualSize", 0):,}</td>
                    <td>{section.get("RawSize", 0):,}</td>
                    <td><span class="badge badge-{entropy_badge}">{entropy:.2f}</span></td>
                    <td><code>{self._escape(section.get("MD5", "N/A")[:16])}...</code></td>
                    <td>{self._escape(chars)}</td>
                </tr>
                """

            content += "</tbody></table>"

        content += "</div>"
        return content

    def _build_imports(self, imports: Dict[str, Any]) -> str:
        """Build detailed imports section"""
        content = f"""
        <div class="section" id="imports">
            <h2>📥 Imports</h2>
        """

        # Suspicious APIs first
        suspicious_apis = imports.get("suspicious_apis", {})
        if suspicious_apis:
            content += "<h3>⚠️ Suspicious APIs Detected</h3>"
            for category, apis in suspicious_apis.items():
                api_badges = " ".join([f'<span class="badge badge-danger">{self._escape(api)}</span>' for api in apis])
                content += f"""
                <div class="warning">
                    <strong>{self._escape(category.replace('_', ' ').title())}</strong><br>
                    {api_badges}
                </div>
                """

        # All Imports by DLL
        import_list = imports.get("imports", [])
        if import_list:
            total_funcs = sum(dll.get("function_count", len(dll.get("functions", []))) for dll in import_list)
            content += f"""
            <h3>Import Table</h3>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="number">{len(import_list)}</div>
                    <div class="label">DLLs</div>
                </div>
                <div class="stat-item">
                    <div class="number">{total_funcs}</div>
                    <div class="label">Functions</div>
                </div>
            </div>
            """

            for dll_import in import_list:
                dll_name = dll_import.get("dll", "Unknown")
                functions = dll_import.get("functions", [])
                func_count = dll_import.get("function_count", len(functions))

                content += f"""
                <button class="collapsible">📁 {self._escape(dll_name)} ({func_count} functions)</button>
                <div class="collapsible-content">
                    <table>
                        <thead>
                            <tr><th>Function</th><th>Address</th><th>Ordinal</th></tr>
                        </thead>
                        <tbody>
                """

                for func in functions:
                    fname = func.get("name", "N/A")
                    faddr = func.get("address", "N/A")
                    fordinal = func.get("ordinal")
                    ordinal_str = str(fordinal) if fordinal is not None else "-"
                    content += f"""
                    <tr>
                        <td><code>{self._escape(fname)}</code></td>
                        <td><code>{self._escape(faddr)}</code></td>
                        <td>{ordinal_str}</td>
                    </tr>
                    """

                content += "</tbody></table></div>"

        content += "</div>"
        return content

    def _build_exports(self, exports: Dict[str, Any]) -> str:
        """Build exports section"""
        export_count = exports.get("count", 0)
        export_functions = exports.get("functions", [])

        content = f"""
        <div class="section" id="exports">
            <h2>📤 Exports</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="number">{export_count}</div>
                    <div class="label">Exported Functions</div>
                </div>
            </div>
        """

        if export_functions:
            content += """
            <table>
                <thead>
                    <tr><th>Function</th><th>Address</th><th>Ordinal</th></tr>
                </thead>
                <tbody>
            """
            for func in export_functions:
                if isinstance(func, dict):
                    fname = func.get("name", "N/A")
                    faddr = func.get("address", "N/A")
                    fordinal = func.get("ordinal", "N/A")
                else:
                    fname = str(func)
                    faddr = "N/A"
                    fordinal = "N/A"
                content += f"""
                <tr>
                    <td><code>{self._escape(fname)}</code></td>
                    <td><code>{self._escape(faddr)}</code></td>
                    <td>{fordinal}</td>
                </tr>
                """
            content += "</tbody></table>"
        else:
            content += '<div class="info"><strong>No exports found</strong></div>'

        content += "</div>"
        return content

    def _build_strings(self, strings: Dict[str, Any]) -> str:
        """Build detailed strings section"""
        total = strings.get("total_count", 0)
        ascii_count = strings.get("ascii_count", 0)
        unicode_count = strings.get("unicode_count", 0)
        categorized = strings.get("categorized", {})
        all_strings = strings.get("all_strings", [])

        content = f"""
        <div class="section" id="strings">
            <h2>🔤 Strings Analysis</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="number">{total}</div>
                    <div class="label">Total Strings</div>
                </div>
                <div class="stat-item">
                    <div class="number">{ascii_count}</div>
                    <div class="label">ASCII</div>
                </div>
                <div class="stat-item">
                    <div class="number">{unicode_count}</div>
                    <div class="label">Unicode</div>
                </div>
            </div>
        """

        # Categorized strings
        if categorized.get("urls"):
            urls = "<br>".join([f'🌐 <code>{self._escape(url)}</code>' for url in categorized["urls"]])
            content += f"""
            <div class="danger">
                <strong>URLs Found ({len(categorized['urls'])})</strong><br>
                {urls}
            </div>
            """

        if categorized.get("ip_addresses"):
            ips = " ".join([f'<span class="badge badge-warning">{self._escape(ip)}</span>' for ip in categorized["ip_addresses"]])
            content += f"""
            <div class="warning">
                <strong>IP Addresses ({len(categorized['ip_addresses'])})</strong><br>
                {ips}
            </div>
            """

        if categorized.get("emails"):
            emails = "<br>".join([f'📧 <code>{self._escape(email)}</code>' for email in categorized["emails"]])
            content += f"""
            <div class="info">
                <strong>Email Addresses ({len(categorized['emails'])})</strong><br>
                {emails}
            </div>
            """

        if categorized.get("registry_keys"):
            keys = "<br>".join([f'🔑 <code>{self._escape(key)}</code>' for key in categorized["registry_keys"]])
            content += f"""
            <div class="warning">
                <strong>Registry Keys ({len(categorized['registry_keys'])})</strong><br>
                {keys}
            </div>
            """

        if categorized.get("file_paths"):
            paths = "<br>".join([f'📁 <code>{self._escape(path)}</code>' for path in categorized["file_paths"]])
            content += f"""
            <div class="info">
                <strong>File Paths ({len(categorized['file_paths'])})</strong><br>
                {paths}
            </div>
            """

        if categorized.get("suspicious_keywords"):
            keywords = " ".join([f'<span class="badge badge-danger">{self._escape(kw)}</span>' for kw in categorized["suspicious_keywords"]])
            content += f"""
            <div class="danger">
                <strong>Suspicious Keywords</strong><br>
                {keywords}
            </div>
            """

        # All strings (collapsible)
        if all_strings:
            escaped_strings = "\n".join([self._escape(s) for s in all_strings])
            content += f"""
            <button class="collapsible">📋 View All Strings ({len(all_strings)} strings)</button>
            <div class="collapsible-content">
                <div class="strings-list">{escaped_strings}</div>
            </div>
            """

        content += "</div>"
        return content

    def _build_disasm(self, disasm: Dict[str, Any]) -> str:
        """Build disassembly analysis section"""
        if not disasm:
            return ""

        entry_point = disasm.get("entry_point", "Unknown")
        total_instructions = disasm.get("total_instructions", 0)
        suspicious = disasm.get("suspicious", [])

        content = f"""
        <div class="section" id="disasm">
            <h2>🔍 Disassembly Analysis</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="number">{entry_point}</div>
                    <div class="label">Entry Point</div>
                </div>
                <div class="stat-item">
                    <div class="number">{total_instructions:,}</div>
                    <div class="label">Instructions Scanned</div>
                </div>
                <div class="stat-item">
                    <div class="number">{len(suspicious)}</div>
                    <div class="label">Suspicious Found</div>
                </div>
            </div>
        """

        if suspicious:
            content += f"""
            <h3>🔍 Suspicious Patterns ({len(suspicious)} found)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Section</th>
                        <th>Address</th>
                        <th>Bytes</th>
                        <th>Instruction</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>
            """

            # Group consecutive repeated instructions
            i = 0
            group_id = 0
            while i < len(suspicious):
                current = suspicious[i]
                current_key = (current.get("section"), current.get("mnemonic"), current.get("bytes"), current.get("reason"))

                start_addr = current.get("address", "")
                all_addresses = [start_addr]
                count = 1
                j = i + 1

                while j < len(suspicious):
                    next_instr = suspicious[j]
                    next_key = (next_instr.get("section"), next_instr.get("mnemonic"), next_instr.get("bytes"), next_instr.get("reason"))
                    if next_key == current_key:
                        all_addresses.append(next_instr.get("address", ""))
                        count += 1
                        j += 1
                    else:
                        break

                end_addr = suspicious[j-1].get("address", "") if count > 1 else None

                section = self._escape(current.get("section", ""))
                bytes_str = self._escape(current.get("bytes", ""))
                instr = f"{current.get('mnemonic', '')} {current.get('operands', '')}".strip()
                reason = self._escape(current.get("reason", ""))

                if count > 1:
                    # Expandable row with all addresses
                    address_display = f"{start_addr} - {end_addr} (x{count})"
                    addresses_list = " ".join([f"<code>{addr}</code>" for addr in all_addresses])
                    content += f"""
                    <tr>
                        <td><code>{section}</code></td>
                        <td>
                            <details>
                                <summary><code>{address_display}</code></summary>
                                <div style="padding: 5px; background: #f8f9fa; margin-top: 5px; border-radius: 4px; max-height: 150px; overflow-y: auto;">
                                    {addresses_list}
                                </div>
                            </details>
                        </td>
                        <td><code>{bytes_str}</code></td>
                        <td><code>{self._escape(instr)}</code></td>
                        <td style="color: #d63384; font-weight: 500;">{reason}</td>
                    </tr>
                    """
                    group_id += 1
                else:
                    content += f"""
                    <tr>
                        <td><code>{section}</code></td>
                        <td><code>{start_addr}</code></td>
                        <td><code>{bytes_str}</code></td>
                        <td><code>{self._escape(instr)}</code></td>
                        <td style="color: #d63384; font-weight: 500;">{reason}</td>
                    </tr>
                    """
                i = j

            content += """
                </tbody>
            </table>
            """
        else:
            content += """
            <div class="success">
                <strong>✅ No suspicious disassembly patterns detected</strong>
            </div>
            """

        content += "</div>"
        return content
