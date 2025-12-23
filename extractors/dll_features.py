"""
DLL-specific Feature Extractor
Extracts features specific to DLL files including exports, forwarded functions,
DLL characteristics, and DLL-specific suspicious indicators.
"""
from typing import Any, Dict, List, Optional
import pefile

from exowin.extractors.base import BaseExtractor


class DLLFeaturesExtractor(BaseExtractor):
    """Extract DLL-specific features for analysis"""

    # Suspicious exported function names often used by malware
    SUSPICIOUS_EXPORT_NAMES = {
        "loader_related": [
            "DllMain", "DllEntryPoint", "DllRegisterServer", "DllUnregisterServer",
            "DllInstall", "DllCanUnloadNow", "DllGetClassObject"
        ],
        "rundll32_abuse": [
            "Control_RunDLL", "Control_RunDLLAsUser", "RundllInstall",
            "EntryPoint", "Main", "Start", "Run", "Exec", "Execute",
            "Launch", "Load", "Init", "Setup", "Install"
        ],
        "proxy_dll": [
            # Common DLL hijacking targets
            "GetFileVersionInfoA", "GetFileVersionInfoW",
            "VerQueryValueA", "VerQueryValueW",
            "GetFileVersionInfoSizeA", "GetFileVersionInfoSizeW"
        ],
        "suspicious_generic": [
            "Inject", "Hook", "Payload", "Shellcode", "Decrypt", "Encrypt",
            "Download", "Upload", "Connect", "Socket", "Reverse", "Bind",
            "Keylog", "Capture", "Steal", "Dump", "Bypass", "Elevate"
        ]
    }

    # Common legitimate Windows DLLs that are often proxied/hijacked
    COMMONLY_HIJACKED_DLLS = [
        "version.dll", "cryptbase.dll", "cryptsp.dll", "dwmapi.dll",
        "profapi.dll", "secur32.dll", "wtsapi32.dll", "userenv.dll",
        "winmm.dll", "winhttp.dll", "wininet.dll", "wship6.dll",
        "wsock32.dll", "ntmarta.dll", "apphelp.dll", "cabinet.dll",
        "comctl32.dll", "dhcpcsvc.dll", "dnsapi.dll", "fwpuclnt.dll",
        "iphlpapi.dll", "mpr.dll", "netapi32.dll", "nlaapi.dll",
        "oleacc.dll", "rasadhlp.dll", "rsaenh.dll", "sspicli.dll",
        "uxtheme.dll", "mswsock.dll", "dbghelp.dll", "dbgcore.dll",
    ]

    # DLL Characteristics flags
    DLL_CHARACTERISTICS = {
        0x0020: "HIGH_ENTROPY_VA",
        0x0040: "DYNAMIC_BASE",  # ASLR
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT",  # DEP
        0x0200: "NO_ISOLATION",
        0x0400: "NO_SEH",
        0x0800: "NO_BIND",
        0x1000: "APPCONTAINER",
        0x2000: "WDM_DRIVER",
        0x4000: "GUARD_CF",  # Control Flow Guard
        0x8000: "TERMINAL_SERVER_AWARE",
    }

    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Extract DLL-specific features"""
        result = {
            "is_dll": pe.is_dll(),
            "dll_info": {},
            "exports": {},
            "dll_characteristics": {},
            "forwarded_functions": [],
            "suspicious_indicators": [],
            "dll_type_analysis": {},
        }

        if not pe.is_dll():
            result["dll_info"]["note"] = "Not a DLL file"
            return result

        # Extract DLL characteristics
        result["dll_characteristics"] = self._extract_dll_characteristics(pe)

        # Extract detailed export information
        result["exports"] = self._extract_detailed_exports(pe)

        # Extract forwarded functions (proxy DLL detection)
        result["forwarded_functions"] = self._extract_forwarded_functions(pe)

        # Analyze DLL type
        result["dll_type_analysis"] = self._analyze_dll_type(pe, filepath)

        # Detect suspicious patterns
        result["suspicious_indicators"] = self._detect_suspicious_patterns(pe, result, filepath)

        # Extract DLL info summary
        result["dll_info"] = self._extract_dll_summary(pe, result, filepath)

        return result

    def _extract_dll_characteristics(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract and interpret DLL characteristics flags"""
        characteristics = {}
        dll_char_value = pe.OPTIONAL_HEADER.DllCharacteristics

        characteristics["raw_value"] = hex(dll_char_value)
        characteristics["flags"] = []

        for flag, name in self.DLL_CHARACTERISTICS.items():
            if dll_char_value & flag:
                characteristics["flags"].append(name)

        # Security features analysis
        characteristics["security_features"] = {
            "aslr_enabled": bool(dll_char_value & 0x0040),
            "dep_enabled": bool(dll_char_value & 0x0100),
            "cfg_enabled": bool(dll_char_value & 0x4000),
            "high_entropy_va": bool(dll_char_value & 0x0020),
            "force_integrity": bool(dll_char_value & 0x0080),
            "no_seh": bool(dll_char_value & 0x0400),
        }

        # Calculate security score (0-100)
        security_score = 0
        if characteristics["security_features"]["aslr_enabled"]:
            security_score += 25
        if characteristics["security_features"]["dep_enabled"]:
            security_score += 25
        if characteristics["security_features"]["cfg_enabled"]:
            security_score += 25
        if characteristics["security_features"]["high_entropy_va"]:
            security_score += 15
        if characteristics["security_features"]["force_integrity"]:
            security_score += 10

        characteristics["security_score"] = security_score

        return characteristics

    def _extract_detailed_exports(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract detailed export table information"""
        exports = {
            "count": 0,
            "functions": [],
            "by_ordinal_only": [],
            "by_name": [],
            "dll_name": None,
            "export_table_rva": None,
            "export_table_size": None,
            "ordinal_base": None,
            "categories": {},
        }

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports

        exp_dir = pe.DIRECTORY_ENTRY_EXPORT

        # Export directory info
        if hasattr(exp_dir, 'struct'):
            exports["ordinal_base"] = exp_dir.struct.Base
            exports["export_table_rva"] = hex(exp_dir.struct.AddressOfFunctions)

        # DLL name from export table
        if hasattr(exp_dir, 'name') and exp_dir.name:
            exports["dll_name"] = exp_dir.name.decode('utf-8') if isinstance(exp_dir.name, bytes) else str(exp_dir.name)

        # Process each export
        for exp in exp_dir.symbols:
            func_info = {
                "ordinal": exp.ordinal,
                "address": hex(exp.address) if exp.address else None,
                "name": None,
                "forwarder": None,
                "is_forwarded": False,
            }

            if exp.name:
                func_info["name"] = exp.name.decode('utf-8') if isinstance(exp.name, bytes) else str(exp.name)
                exports["by_name"].append(func_info["name"])
            else:
                exports["by_ordinal_only"].append(exp.ordinal)

            # Check for forwarded export
            if exp.forwarder:
                func_info["forwarder"] = exp.forwarder.decode('utf-8') if isinstance(exp.forwarder, bytes) else str(exp.forwarder)
                func_info["is_forwarded"] = True

            exports["functions"].append(func_info)

        exports["count"] = len(exports["functions"])
        exports["named_count"] = len(exports["by_name"])
        exports["ordinal_only_count"] = len(exports["by_ordinal_only"])

        # Categorize exports
        exports["categories"] = self._categorize_exports(exports["by_name"])

        return exports

    def _categorize_exports(self, export_names: List[str]) -> Dict[str, List[str]]:
        """Categorize exported functions by type"""
        categories = {
            "com_related": [],
            "rundll32_compatible": [],
            "standard_dll": [],
            "suspicious": [],
            "other": [],
        }

        com_patterns = ["DllGetClassObject", "DllCanUnloadNow", "DllRegisterServer",
                        "DllUnregisterServer", "DllInstall"]

        for name in export_names:
            name_lower = name.lower()

            # COM-related exports
            if any(pattern.lower() in name_lower for pattern in com_patterns):
                categories["com_related"].append(name)
            # Rundll32 compatible (callable from rundll32)
            elif any(sus.lower() in name_lower for sus in self.SUSPICIOUS_EXPORT_NAMES["rundll32_abuse"]):
                categories["rundll32_compatible"].append(name)
            # Standard DLL exports (DllMain, etc.)
            elif any(std.lower() in name_lower for std in self.SUSPICIOUS_EXPORT_NAMES["loader_related"]):
                categories["standard_dll"].append(name)
            # Suspicious names
            elif any(sus.lower() in name_lower for sus in self.SUSPICIOUS_EXPORT_NAMES["suspicious_generic"]):
                categories["suspicious"].append(name)
            else:
                categories["other"].append(name)

        return categories

    def _extract_forwarded_functions(self, pe: pefile.PE) -> List[Dict[str, Any]]:
        """Extract forwarded functions (potential proxy DLL indicators)"""
        forwarded = []

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return forwarded

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.forwarder:
                forwarder_str = exp.forwarder.decode('utf-8') if isinstance(exp.forwarder, bytes) else str(exp.forwarder)

                # Parse forwarder string (format: "DLL.FunctionName" or "DLL.#Ordinal")
                target_dll = None
                target_func = None
                if '.' in forwarder_str:
                    parts = forwarder_str.split('.', 1)
                    target_dll = parts[0]
                    target_func = parts[1] if len(parts) > 1 else None

                forwarded.append({
                    "export_name": exp.name.decode('utf-8') if exp.name and isinstance(exp.name, bytes) else str(exp.name) if exp.name else f"Ordinal_{exp.ordinal}",
                    "ordinal": exp.ordinal,
                    "forwarder": forwarder_str,
                    "target_dll": target_dll,
                    "target_function": target_func,
                })

        return forwarded

    def _analyze_dll_type(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Analyze the type of DLL based on its characteristics"""
        analysis = {
            "type": "unknown",
            "subtypes": [],
            "is_com_dll": False,
            "is_proxy_dll": False,
            "is_service_dll": False,
            "is_control_panel": False,
            "is_shell_extension": False,
            "has_dllmain": False,
            "rundll32_callable": False,
        }

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            analysis["type"] = "no_exports"
            return analysis

        export_names = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                name = exp.name.decode('utf-8') if isinstance(exp.name, bytes) else str(exp.name)
                export_names.append(name)

        export_names_lower = [n.lower() for n in export_names]

        # Check for COM DLL
        com_exports = ["dllgetclassobject", "dllcanunloadnow"]
        if all(exp in export_names_lower for exp in com_exports):
            analysis["is_com_dll"] = True
            analysis["subtypes"].append("COM_DLL")

        # Check for registration functions
        if "dllregisterserver" in export_names_lower:
            analysis["subtypes"].append("SELF_REGISTERING")

        # Check for DllMain
        if "dllmain" in export_names_lower or "_dllmain@12" in export_names_lower:
            analysis["has_dllmain"] = True

        # Check for Control Panel applet
        if "cplapplet" in export_names_lower:
            analysis["is_control_panel"] = True
            analysis["subtypes"].append("CONTROL_PANEL_APPLET")

        # Check for Service DLL
        if "servicemain" in export_names_lower:
            analysis["is_service_dll"] = True
            analysis["subtypes"].append("SERVICE_DLL")

        # Check for rundll32 callable
        rundll_patterns = ["run", "exec", "execute", "main", "start", "entry", "launch", "init"]
        if any(pattern in n for n in export_names_lower for pattern in rundll_patterns):
            analysis["rundll32_callable"] = True
            analysis["subtypes"].append("RUNDLL32_CALLABLE")

        # Check for Shell Extension
        shell_exports = ["dllgetclassobject", "dllcanunloadnow"]
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8').lower() if isinstance(entry.dll, bytes) else str(entry.dll).lower()
                if "shell32" in dll_name or "shlwapi" in dll_name:
                    if all(exp in export_names_lower for exp in shell_exports):
                        analysis["is_shell_extension"] = True
                        analysis["subtypes"].append("SHELL_EXTENSION")
                    break

        # Check for proxy DLL
        forwarded_count = sum(1 for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.forwarder)
        total_exports = len(list(pe.DIRECTORY_ENTRY_EXPORT.symbols))
        if total_exports > 0 and forwarded_count / total_exports > 0.5:
            analysis["is_proxy_dll"] = True
            analysis["subtypes"].append("PROXY_DLL")

        # Determine main type
        if analysis["is_com_dll"]:
            analysis["type"] = "COM_DLL"
        elif analysis["is_service_dll"]:
            analysis["type"] = "SERVICE_DLL"
        elif analysis["is_control_panel"]:
            analysis["type"] = "CONTROL_PANEL"
        elif analysis["is_proxy_dll"]:
            analysis["type"] = "PROXY_DLL"
        elif analysis["is_shell_extension"]:
            analysis["type"] = "SHELL_EXTENSION"
        elif analysis["rundll32_callable"]:
            analysis["type"] = "RUNDLL32_DLL"
        else:
            analysis["type"] = "STANDARD_DLL"

        return analysis

    def _detect_suspicious_patterns(self, pe: pefile.PE, result: Dict, filepath: str = None) -> List[Dict[str, Any]]:
        """Detect suspicious patterns specific to DLLs"""
        indicators = []

        # Check for suspicious exported names
        exports = result.get("exports", {})
        suspicious_exports = exports.get("categories", {}).get("suspicious", [])
        if suspicious_exports:
            indicators.append({
                "type": "suspicious_exports",
                "severity": "high",
                "description": f"Suspicious export names detected: {', '.join(suspicious_exports[:5])}",
                "details": suspicious_exports
            })

        # Check for many rundll32 callable exports
        rundll_exports = exports.get("categories", {}).get("rundll32_compatible", [])
        if len(rundll_exports) > 3:
            indicators.append({
                "type": "rundll32_abuse_potential",
                "severity": "medium",
                "description": f"Multiple rundll32-callable exports ({len(rundll_exports)} found)",
                "details": rundll_exports
            })

        # Check for proxy DLL (high forwarding ratio)
        if result.get("dll_type_analysis", {}).get("is_proxy_dll"):
            forwarded = result.get("forwarded_functions", [])
            indicators.append({
                "type": "proxy_dll",
                "severity": "medium",
                "description": f"Possible proxy/DLL hijacking - {len(forwarded)} forwarded exports",
                "details": [f["export_name"] for f in forwarded[:10]]
            })

        # Check for commonly hijacked DLL name
        if filepath:
            import os
            filename = os.path.basename(filepath).lower()
            if filename in self.COMMONLY_HIJACKED_DLLS:
                indicators.append({
                    "type": "dll_hijacking_target",
                    "severity": "info",
                    "description": f"Filename '{filename}' is a common DLL hijacking target",
                    "details": {"filename": filename}
                })

        # Check for no ASLR/DEP
        dll_chars = result.get("dll_characteristics", {}).get("security_features", {})
        if not dll_chars.get("aslr_enabled"):
            indicators.append({
                "type": "no_aslr",
                "severity": "low",
                "description": "ASLR (Address Space Layout Randomization) is disabled",
                "details": {}
            })
        if not dll_chars.get("dep_enabled"):
            indicators.append({
                "type": "no_dep",
                "severity": "low",
                "description": "DEP (Data Execution Prevention) compatibility is disabled",
                "details": {}
            })

        # Check for exports by ordinal only (can hide function purpose)
        ordinal_only = exports.get("ordinal_only_count", 0)
        total = exports.get("count", 0)
        if total > 0 and ordinal_only > 0:
            ratio = ordinal_only / total
            if ratio > 0.5:
                indicators.append({
                    "type": "ordinal_exports",
                    "severity": "medium",
                    "description": f"High ratio of ordinal-only exports ({ordinal_only}/{total}) - may hide function names",
                    "details": {"ordinal_only": ordinal_only, "total": total, "ratio": round(ratio, 2)}
                })

        # Check for DLL without any exports (suspicious for loaded DLL)
        if total == 0:
            indicators.append({
                "type": "no_exports",
                "severity": "medium",
                "description": "DLL has no exports - unusual for a legitimate DLL",
                "details": {}
            })

        return indicators

    def _extract_dll_summary(self, pe: pefile.PE, result: Dict, filepath: str = None) -> Dict[str, Any]:
        """Create a summary of DLL information"""
        import os

        exports = result.get("exports", {})
        dll_type = result.get("dll_type_analysis", {})
        dll_chars = result.get("dll_characteristics", {})
        indicators = result.get("suspicious_indicators", [])

        summary = {
            "filename": os.path.basename(filepath) if filepath else None,
            "dll_type": dll_type.get("type", "unknown"),
            "subtypes": dll_type.get("subtypes", []),
            "export_count": exports.get("count", 0),
            "named_exports": exports.get("named_count", 0),
            "ordinal_exports": exports.get("ordinal_only_count", 0),
            "forwarded_exports": len(result.get("forwarded_functions", [])),
            "security_score": dll_chars.get("security_score", 0),
            "security_features": dll_chars.get("security_features", {}),
            "suspicious_count": len(indicators),
            "high_severity_count": len([i for i in indicators if i.get("severity") == "high"]),
        }

        # Risk assessment
        risk_score = 0
        for ind in indicators:
            if ind.get("severity") == "high":
                risk_score += 30
            elif ind.get("severity") == "medium":
                risk_score += 15
            elif ind.get("severity") == "low":
                risk_score += 5

        if risk_score > 60:
            summary["risk_level"] = "HIGH"
        elif risk_score > 30:
            summary["risk_level"] = "MEDIUM"
        elif risk_score > 0:
            summary["risk_level"] = "LOW"
        else:
            summary["risk_level"] = "NONE"

        summary["risk_score"] = min(100, risk_score)

        return summary


class DLLMLFeaturesExtractor(BaseExtractor):
    """Extract numerical ML features specific to DLL analysis"""

    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Extract numerical features for ML from DLL"""
        features = {}

        features["is_dll"] = 1 if pe.is_dll() else 0

        if not pe.is_dll():
            # Return minimal features for non-DLL
            features.update(self._get_default_dll_features())
            return features

        # DLL Characteristics features
        dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
        features["dll_char_aslr"] = 1 if dll_char & 0x0040 else 0
        features["dll_char_dep"] = 1 if dll_char & 0x0100 else 0
        features["dll_char_cfg"] = 1 if dll_char & 0x4000 else 0
        features["dll_char_high_entropy"] = 1 if dll_char & 0x0020 else 0
        features["dll_char_no_seh"] = 1 if dll_char & 0x0400 else 0
        features["dll_char_force_integrity"] = 1 if dll_char & 0x0080 else 0
        features["dll_char_raw"] = dll_char

        # Calculate security score
        features["dll_security_score"] = (
            features["dll_char_aslr"] * 25 +
            features["dll_char_dep"] * 25 +
            features["dll_char_cfg"] * 25 +
            features["dll_char_high_entropy"] * 15 +
            features["dll_char_force_integrity"] * 10
        )

        # Export features
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = list(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            features["dll_export_count"] = len(exports)

            named_count = sum(1 for e in exports if e.name)
            features["dll_export_named_count"] = named_count
            features["dll_export_ordinal_only_count"] = len(exports) - named_count

            forwarded_count = sum(1 for e in exports if e.forwarder)
            features["dll_export_forwarded_count"] = forwarded_count

            if len(exports) > 0:
                features["dll_export_forwarded_ratio"] = round(forwarded_count / len(exports), 4)
                features["dll_export_ordinal_ratio"] = round((len(exports) - named_count) / len(exports), 4)
            else:
                features["dll_export_forwarded_ratio"] = 0.0
                features["dll_export_ordinal_ratio"] = 0.0

            # Check for suspicious export names
            suspicious_count = 0
            rundll_count = 0
            com_count = 0

            suspicious_keywords = ["inject", "hook", "payload", "shellcode", "decrypt", "encrypt",
                                   "download", "upload", "keylog", "capture", "steal", "bypass"]
            rundll_keywords = ["run", "exec", "execute", "main", "start", "entry", "launch"]
            com_keywords = ["dllgetclassobject", "dllcanunloadnow", "dllregisterserver"]

            for exp in exports:
                if exp.name:
                    name_lower = exp.name.decode('utf-8').lower() if isinstance(exp.name, bytes) else str(exp.name).lower()

                    if any(k in name_lower for k in suspicious_keywords):
                        suspicious_count += 1
                    if any(k in name_lower for k in rundll_keywords):
                        rundll_count += 1
                    if any(k in name_lower for k in com_keywords):
                        com_count += 1

            features["dll_suspicious_export_count"] = suspicious_count
            features["dll_rundll_export_count"] = rundll_count
            features["dll_com_export_count"] = com_count
        else:
            features.update(self._get_default_export_features())

        # DLL type indicators
        features["dll_is_com"] = 1 if features.get("dll_com_export_count", 0) >= 2 else 0
        features["dll_is_proxy"] = 1 if features.get("dll_export_forwarded_ratio", 0) > 0.5 else 0
        features["dll_has_exports"] = 1 if features.get("dll_export_count", 0) > 0 else 0

        return features

    def _get_default_dll_features(self) -> Dict[str, Any]:
        """Return default DLL features for non-DLL files"""
        return {
            "dll_char_aslr": 0,
            "dll_char_dep": 0,
            "dll_char_cfg": 0,
            "dll_char_high_entropy": 0,
            "dll_char_no_seh": 0,
            "dll_char_force_integrity": 0,
            "dll_char_raw": 0,
            "dll_security_score": 0,
            "dll_export_count": 0,
            "dll_export_named_count": 0,
            "dll_export_ordinal_only_count": 0,
            "dll_export_forwarded_count": 0,
            "dll_export_forwarded_ratio": 0.0,
            "dll_export_ordinal_ratio": 0.0,
            "dll_suspicious_export_count": 0,
            "dll_rundll_export_count": 0,
            "dll_com_export_count": 0,
            "dll_is_com": 0,
            "dll_is_proxy": 0,
            "dll_has_exports": 0,
        }

    def _get_default_export_features(self) -> Dict[str, Any]:
        """Return default export features"""
        return {
            "dll_export_count": 0,
            "dll_export_named_count": 0,
            "dll_export_ordinal_only_count": 0,
            "dll_export_forwarded_count": 0,
            "dll_export_forwarded_ratio": 0.0,
            "dll_export_ordinal_ratio": 0.0,
            "dll_suspicious_export_count": 0,
            "dll_rundll_export_count": 0,
            "dll_com_export_count": 0,
        }

    def get_feature_names(self) -> List[str]:
        """Return list of all DLL ML feature names"""
        return [
            "is_dll",
            "dll_char_aslr",
            "dll_char_dep",
            "dll_char_cfg",
            "dll_char_high_entropy",
            "dll_char_no_seh",
            "dll_char_force_integrity",
            "dll_char_raw",
            "dll_security_score",
            "dll_export_count",
            "dll_export_named_count",
            "dll_export_ordinal_only_count",
            "dll_export_forwarded_count",
            "dll_export_forwarded_ratio",
            "dll_export_ordinal_ratio",
            "dll_suspicious_export_count",
            "dll_rundll_export_count",
            "dll_com_export_count",
            "dll_is_com",
            "dll_is_proxy",
            "dll_has_exports",
        ]
