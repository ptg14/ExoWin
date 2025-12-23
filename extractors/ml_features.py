"""
ML Feature Extractor - Extract numerical features for Machine Learning
"""
import math
import os
import re
import time
import datetime
from collections import Counter
from typing import Any, Dict, List
import pefile
import hashlib

from exowin.extractors.base import BaseExtractor


class MLFeaturesExtractor(BaseExtractor):
    """Extract numerical features suitable for Machine Learning"""

    # Suspicious API categories for counting
    SUSPICIOUS_API_CATEGORIES = {
        "process_injection": [
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "OpenProcess", "VirtualProtectEx", "SetThreadContext", "ResumeThread",
            "QueueUserAPC", "NtQueueApcThread", "RtlCreateUserThread"
        ],
        "keylogging": [
            "SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow",
            "GetKeyState", "AttachThreadInput"
        ],
        "anti_debugging": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugString", "FindWindow", "NtSetInformationThread"
        ],
        "network": [
            "InternetOpen", "InternetOpenUrl", "InternetReadFile", "URLDownloadToFile",
            "HttpSendRequest", "HttpOpenRequest", "InternetConnect", "send", "recv",
            "WSAStartup", "socket", "connect", "bind", "listen", "accept"
        ],
        "registry": [
            "RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx",
            "RegDeleteKey", "RegDeleteValue", "RegOpenKey", "RegOpenKeyEx"
        ],
        "file_operations": [
            "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "CopyFile",
            "MoveFile", "FindFirstFile", "FindNextFile"
        ],
        "persistence": [
            "CreateService", "StartService", "OpenSCManager", "RegisterServiceCtrlHandler",
            "SetWindowsHookEx", "SHSetValue"
        ],
        "crypto": [
            "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
            "CryptHashData", "CryptDeriveKey"
        ],
        "anti_vm": [
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next"
        ]
    }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        p, lns = Counter(data), float(len(data))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Extract ML-ready numerical features from PE file"""
        features = {}

        # File-level features
        features.update(self._extract_file_features(pe))

        # String / IOC features (scans raw)
        features.update(self._extract_string_features(pe))

        # DOS Header features
        features.update(self._extract_dos_header_features(pe))

        # File Header features
        features.update(self._extract_file_header_features(pe))

        # Optional Header features
        features.update(self._extract_optional_header_features(pe))

        # Section features
        features.update(self._extract_section_features(pe))

        # Import features
        features.update(self._extract_import_features(pe))

        # Export features
        features.update(self._extract_export_features(pe))

        # Resource features
        features.update(self._extract_resource_features(pe))

        # Data directory features
        features.update(self._extract_data_directory_features(pe))

        # Behavioral boolean indicators
        try:
            features['has_anti_debugging'] = 1 if features.get('imp_sus_anti_debugging', 0) > 0 else 0
            features['has_injection_apis'] = 1 if features.get('imp_sus_process_injection', 0) > 0 else 0
            features['has_network_apis'] = 1 if features.get('imp_sus_network', 0) > 0 else 0
            features['has_filesystem_apis'] = 1 if features.get('imp_sus_file_operations', 0) > 0 else 0
            features['has_persistence_apis'] = 1 if features.get('imp_sus_persistence', 0) > 0 else 0
        except Exception:
            features['has_anti_debugging'] = 0
            features['has_injection_apis'] = 0
            features['has_network_apis'] = 0
            features['has_filesystem_apis'] = 0
            features['has_persistence_apis'] = 0

        # File hashes and magic bytes
        try:
            raw = bytes(pe.__data__)
            features['md5'] = hashlib.md5(raw).hexdigest()
            features['sha1'] = hashlib.sha1(raw).hexdigest()
            features['sha256'] = hashlib.sha256(raw).hexdigest()
            try:
                features['magic_bytes'] = raw[:4].hex()
            except Exception:
                features['magic_bytes'] = ''
        except Exception:
            features['md5'] = ''
            features['sha1'] = ''
            features['sha256'] = ''
            features['magic_bytes'] = ''

        # Statistical byte features
        try:
            raw = bytes(pe.__data__)
            counts = Counter(raw)
            total = len(raw)
            # printable ASCII bytes 32..126
            printable = sum(counts[b] for b in range(32, 127) if b in counts)
            features['printable_ratio'] = round(printable / max(1, total), 4)
            # byte value stddev
            mean = sum(b * counts[b] for b in counts) / max(1, total)
            variance = sum(((b - mean) ** 2) * counts[b] for b in counts) / max(1, total)
            features['byte_stddev'] = round(math.sqrt(variance), 4)
        except Exception:
            features['printable_ratio'] = 0.0
            features['byte_stddev'] = 0.0

        # Code/data ratio
        try:
            features['sec_code_data_ratio'] = round(
                features.get('sec_num_code', 0) / max(1, features.get('sec_num_data', 0)), 4
            )
        except Exception:
            features['sec_code_data_ratio'] = 0.0

        # Version info presence
        try:
            has_ver = 0
            ver_count = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    # resource id 16 == RT_VERSION
                    if getattr(entry, 'id', None) == 16 or (hasattr(entry, 'name') and str(entry.name).lower().find('version') != -1):
                        has_ver = 1
                        ver_count += 1
            features['has_version_info'] = has_ver
            features['version_string_count'] = ver_count
        except Exception:
            features['has_version_info'] = 0
            features['version_string_count'] = 0

        # Heuristic scores - pack and anomaly indicators
        try:
            packed_raw = 0.0
            packed_raw += 1.0 if features.get('overlay_size', 0) > 0 else 0.0
            packed_raw += 0.5 * features.get('sec_num_suspicious_entropy', 0)
            packed_raw += 1.0 * features.get('sec_num_wx', 0)
            packed_raw += 0.5 * features.get('sec_name_suspicious_count', 0)
            sec_count = max(1, features.get('sec_num_sections', 1))
            features['packed_score'] = round(min(1.0, packed_raw / (1.0 + sec_count/2.0)), 4)
        except Exception:
            features['packed_score'] = 0.0

        try:
            raw_anom = 0.0
            raw_anom += features.get('imp_sus_total', 0)
            raw_anom += 2 * features.get('sec_num_suspicious_entropy', 0)
            raw_anom += 2 * features.get('sec_num_wx', 0)
            raw_anom += 3 if features.get('overlay_size', 0) > 0 else 0
            raw_anom += features.get('suspicious_string_patterns_count', 0)
            features['anomaly_score'] = round(min(1.0, raw_anom / (5.0 + sec_count)), 4)
        except Exception:
            features['anomaly_score'] = 0.0

        # DLL-specific features
        features.update(self._extract_dll_features(pe))

        return features

    def _extract_file_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract file-level features"""
        raw = bytes(pe.__data__)
        entropy = self.calculate_entropy(raw)

        # Overlay detection (data after last section raw end)
        overlay_size = 0
        try:
            last_raw_end = 0
            for s in pe.sections:
                end = s.PointerToRawData + s.SizeOfRawData
                if end > last_raw_end:
                    last_raw_end = end

            file_size = len(raw)
            if file_size > last_raw_end:
                overlay_size = file_size - last_raw_end
        except Exception:
            overlay_size = 0

        # Timestamp analysis
        try:
            timestamp = int(pe.FILE_HEADER.TimeDateStamp)
            now = int(time.time())
            timestamp_age_days = (now - timestamp) / 86400 if timestamp > 0 else -1
            timestamp_zero = 1 if timestamp == 0 else 0
        except Exception:
            timestamp = 0
            timestamp_age_days = -1
            timestamp_zero = 1

        # File mtime mismatch
        file_mtime_mismatch = 0
        try:
            if hasattr(pe, 'name') and pe.name:
                path = pe.name
            else:
                path = None
            # filepath may be provided to extract via caller; try to get it from PE if available
            # We don't have filepath here reliably, so skip strict check (caller can add metadata)
        except Exception:
            path = None

        # Certificate presence (SECURITY data directory index is 4)
        try:
            sec_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            has_cert = 1 if getattr(sec_entry, 'Size', 0) and getattr(sec_entry, 'VirtualAddress', 0) else 0
        except Exception:
            has_cert = 0

        result = {
            "file_size": len(raw),
            "file_entropy": round(entropy, 4),
            "file_entropy_high": 1 if entropy > 7.0 else 0,
            "file_entropy_packed": 1 if entropy > 6.5 else 0,
            "overlay_size": overlay_size,
            "timestamp": timestamp,
            "timestamp_zero": timestamp_zero,
            "timestamp_age_days": round(timestamp_age_days, 2) if timestamp_age_days >= 0 else -1,
            "file_mtime_mismatch": file_mtime_mismatch,
            "has_cert": has_cert,
        }

        return result

    def _extract_dos_header_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract DOS header features"""
        return {
            "dos_e_magic": pe.DOS_HEADER.e_magic,
            "dos_e_lfanew": pe.DOS_HEADER.e_lfanew,
        }

    def _extract_string_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract simple string/I O C counts from raw data"""
        raw = bytes(pe.__data__)

        # ASCII strings of length >=4
        pattern = rb"[ -~]{4,}"  # printable ascii
        strs = re.findall(pattern, raw)
        str_lens = [len(s) for s in strs]

        # URL and IP patterns
        url_re = re.compile(rb"https?://[A-Za-z0-9_./?=#%&:-]{4,}")
        ip_re = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

        urls = url_re.findall(raw)
        ips = ip_re.findall(raw)
        # emails
        email_re = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        emails = email_re.findall(raw)

        # file paths (windows/simple unix)
        path_re = re.compile(rb"[A-Za-z]:\\[\w\\\-\. ]{2,}|/usr/[A-Za-z0-9_/-]{3,}")
        paths = path_re.findall(raw)

        # base64-like (very heuristic)
        b64_re = re.compile(rb"(?:[A-Za-z0-9+/]{40,}={0,2})")
        b64s = b64_re.findall(raw)

        features = {
            "extracted_strings_count": len(strs),
            "extracted_strings_avg_len": round(sum(str_lens) / len(str_lens), 2) if str_lens else 0,
            "extracted_strings_max_len": max(str_lens) if str_lens else 0,
            "res_string_url_count": len(urls),
            "res_string_ip_count": len(ips),
            "res_string_email_count": len(emails),
            "res_string_path_count": len(paths),
            "res_string_base64_count": len(b64s),
        }

        # Suspicious string patterns (registry keys, mutex, service names simple heuristics)
        suspicious = 0
        try:
            for s in strs:
                sl = s.lower()
                if b"software\\microsoft" in sl or b"services\\" in sl or b"mutex" in sl or b"base64" in sl:
                    suspicious += 1
        except Exception:
            suspicious = 0

        features["suspicious_string_patterns_count"] = suspicious

        return features

    def _extract_file_header_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract COFF file header features"""
        fh = pe.FILE_HEADER

        return {
            "fh_machine": fh.Machine,
            "fh_num_sections": fh.NumberOfSections,
            "fh_timestamp": fh.TimeDateStamp,
            "fh_ptr_symbol_table": fh.PointerToSymbolTable,
            "fh_num_symbols": fh.NumberOfSymbols,
            "fh_size_opt_header": fh.SizeOfOptionalHeader,
            "fh_characteristics": fh.Characteristics,
            # Characteristic flags
            "fh_char_relocs_stripped": 1 if fh.Characteristics & 0x0001 else 0,
            "fh_char_executable": 1 if fh.Characteristics & 0x0002 else 0,
            "fh_char_large_address": 1 if fh.Characteristics & 0x0020 else 0,
            "fh_char_32bit": 1 if fh.Characteristics & 0x0100 else 0,
            "fh_char_debug_stripped": 1 if fh.Characteristics & 0x0200 else 0,
            "fh_char_dll": 1 if fh.Characteristics & 0x2000 else 0,
        }

    def _extract_optional_header_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract optional header features"""
        oh = pe.OPTIONAL_HEADER

        features = {
            "oh_magic": oh.Magic,
            "oh_major_linker_ver": oh.MajorLinkerVersion,
            "oh_minor_linker_ver": oh.MinorLinkerVersion,
            "oh_size_of_code": oh.SizeOfCode,
            "oh_size_of_init_data": oh.SizeOfInitializedData,
            "oh_size_of_uninit_data": oh.SizeOfUninitializedData,
            "oh_entry_point": oh.AddressOfEntryPoint,
            "oh_base_of_code": oh.BaseOfCode,
            "oh_image_base": oh.ImageBase,
            "oh_section_alignment": oh.SectionAlignment,
            "oh_file_alignment": oh.FileAlignment,
            "oh_major_os_ver": oh.MajorOperatingSystemVersion,
            "oh_minor_os_ver": oh.MinorOperatingSystemVersion,
            "oh_major_image_ver": oh.MajorImageVersion,
            "oh_minor_image_ver": oh.MinorImageVersion,
            "oh_major_subsystem_ver": oh.MajorSubsystemVersion,
            "oh_minor_subsystem_ver": oh.MinorSubsystemVersion,
            "oh_size_of_image": oh.SizeOfImage,
            "oh_size_of_headers": oh.SizeOfHeaders,
            "oh_checksum": oh.CheckSum,
            "oh_subsystem": oh.Subsystem,
            "oh_dll_characteristics": oh.DllCharacteristics,
            "oh_size_stack_reserve": oh.SizeOfStackReserve,
            "oh_size_stack_commit": oh.SizeOfStackCommit,
            "oh_size_heap_reserve": oh.SizeOfHeapReserve,
            "oh_size_heap_commit": oh.SizeOfHeapCommit,
            "oh_num_rva_sizes": oh.NumberOfRvaAndSizes,
            # DLL Characteristic flags
            "oh_dll_char_dynamic_base": 1 if oh.DllCharacteristics & 0x0040 else 0,
            "oh_dll_char_force_integrity": 1 if oh.DllCharacteristics & 0x0080 else 0,
            "oh_dll_char_nx_compat": 1 if oh.DllCharacteristics & 0x0100 else 0,
            "oh_dll_char_no_isolation": 1 if oh.DllCharacteristics & 0x0200 else 0,
            "oh_dll_char_no_seh": 1 if oh.DllCharacteristics & 0x0400 else 0,
            "oh_dll_char_no_bind": 1 if oh.DllCharacteristics & 0x0800 else 0,
            "oh_dll_char_wdm_driver": 1 if oh.DllCharacteristics & 0x2000 else 0,
            "oh_dll_char_terminal_server": 1 if oh.DllCharacteristics & 0x8000 else 0,
        }

        # PE type
        features["is_exe"] = 1 if pe.is_exe() else 0
        features["is_dll"] = 1 if pe.is_dll() else 0
        features["is_driver"] = 1 if pe.is_driver() else 0

        return features

    def _extract_section_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract section-related features"""
        features = {
            "sec_num_sections": len(pe.sections),
            "sec_total_entropy": 0.0,
            "sec_avg_entropy": 0.0,
            "sec_max_entropy": 0.0,
            "sec_min_entropy": 8.0,
            "sec_total_raw_size": 0,
            "sec_total_virtual_size": 0,
            "sec_num_executable": 0,
            "sec_num_writable": 0,
            "sec_num_readable": 0,
            "sec_num_code": 0,
            "sec_num_data": 0,
            "sec_num_suspicious_entropy": 0,
            "sec_num_wx": 0,  # Writable and Executable
            "sec_size_mismatch_count": 0,
            "sec_name_suspicious_count": 0,
            "sec_virtual_vs_raw_ratio_max": 0.0,
            "sec_virtual_vs_raw_ratio_avg": 0.0,
            "sec_unmapped_entry_point": 0,
        }

        entropies = []
        ratios = []

        for section in pe.sections:
            section_data = section.get_data()
            entropy = self.calculate_entropy(section_data)
            entropies.append(entropy)

            features["sec_total_raw_size"] += section.SizeOfRawData
            features["sec_total_virtual_size"] += section.Misc_VirtualSize

            # Characteristics
            is_executable = bool(section.Characteristics & 0x20000000)
            is_writable = bool(section.Characteristics & 0x80000000)
            is_readable = bool(section.Characteristics & 0x40000000)
            is_code = bool(section.Characteristics & 0x00000020)
            is_data = bool(section.Characteristics & 0x00000040)

            if is_executable:
                features["sec_num_executable"] += 1
            if is_writable:
                features["sec_num_writable"] += 1
            if is_readable:
                features["sec_num_readable"] += 1
            if is_code:
                features["sec_num_code"] += 1
            if is_data:
                features["sec_num_data"] += 1

            # Suspicious: writable and executable
            if is_writable and is_executable:
                features["sec_num_wx"] += 1

            # High entropy sections
            if entropy > 7.0:
                features["sec_num_suspicious_entropy"] += 1

            # Size mismatch
            if section.Misc_VirtualSize > 0:
                ratio = abs(section.SizeOfRawData - section.Misc_VirtualSize) / section.Misc_VirtualSize
                if ratio > 0.5:
                    features["sec_size_mismatch_count"] += 1

            # Virtual/raw ratio
            try:
                if section.Misc_VirtualSize > 0:
                    vr = section.Misc_VirtualSize / max(1, section.SizeOfRawData)
                    ratios.append(vr)
            except Exception:
                pass

            # Suspicious section names
            try:
                name = section.Name.decode('utf-8').rstrip('\x00').lower()
            except Exception:
                name = str(section.Name).lower()

            suspicious_names = ['.packed', '.upx', '.aspack', '.adata', '.boom', 'padded', '.rsrc_pad']
            if any(sn in name for sn in suspicious_names):
                features["sec_name_suspicious_count"] += 1

        if entropies:
            features["sec_total_entropy"] = round(sum(entropies), 4)
            features["sec_avg_entropy"] = round(sum(entropies) / len(entropies), 4)
            features["sec_max_entropy"] = round(max(entropies), 4)
            features["sec_min_entropy"] = round(min(entropies), 4)

        if ratios:
            features["sec_virtual_vs_raw_ratio_max"] = round(max(ratios), 4)
            features["sec_virtual_vs_raw_ratio_avg"] = round(sum(ratios) / len(ratios), 4)

        # Check if entry point mapped to a section
        try:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_rva = ep
            mapped = False
            for s in pe.sections:
                if s.VirtualAddress <= ep_rva < (s.VirtualAddress + max(1, s.Misc_VirtualSize)):
                    mapped = True
                    break
            features["sec_unmapped_entry_point"] = 0 if mapped else 1
        except Exception:
            features["sec_unmapped_entry_point"] = 0

        return features

    def _extract_import_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract import-related features"""
        features = {
            "imp_num_dlls": 0,
            "imp_num_functions": 0,
            "imp_avg_functions_per_dll": 0.0,
            "imp_by_ordinal_count": 0,
            "imp_thunk_count": 0,
            "imp_unusual_dlls_count": 0,
            "imp_delay_import_count": 0,
        }

        # Initialize suspicious API counters
        for category in self.SUSPICIOUS_API_CATEGORIES:
            features[f"imp_sus_{category}"] = 0

        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            # still check for delay imports
            if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                features["imp_delay_import_count"] = len(pe.DIRECTORY_ENTRY_DELAY_IMPORT)
            return features

        all_functions = []

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            features["imp_num_dlls"] += 1
            dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else str(entry.dll)
            # Common system DLLs
            common = ['kernel32.dll','ntdll.dll','advapi32.dll','ws2_32.dll','user32.dll','gdi32.dll','shell32.dll','ole32.dll','msvcrt.dll','comctl32.dll']
            if dll_name.lower() not in common:
                features["imp_unusual_dlls_count"] += 1

            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else str(imp.name)
                    all_functions.append(func_name)
                    features["imp_num_functions"] += 1
                else:
                    # imported by ordinal or thunk
                    if getattr(imp, 'ordinal', None):
                        features["imp_by_ordinal_count"] += 1
                    else:
                        features["imp_thunk_count"] += 1

        # Calculate average
        if features["imp_num_dlls"] > 0:
            features["imp_avg_functions_per_dll"] = round(
                features["imp_num_functions"] / features["imp_num_dlls"], 2
            )

        # Count suspicious APIs
        for category, api_list in self.SUSPICIOUS_API_CATEGORIES.items():
            count = sum(1 for func in all_functions if func in api_list)
            features[f"imp_sus_{category}"] = count

        # Total suspicious API count
        features["imp_sus_total"] = sum(
            features[f"imp_sus_{cat}"] for cat in self.SUSPICIOUS_API_CATEGORIES
        )

        # Delay imports
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            try:
                features["imp_delay_import_count"] = len(pe.DIRECTORY_ENTRY_DELAY_IMPORT)
            except Exception:
                features["imp_delay_import_count"] = 0

        # Suspicious API ratio
        try:
            features["imp_suspicious_api_ratio"] = round(
                features["imp_sus_total"] / max(1, features["imp_num_functions"]), 4
            )
        except Exception:
            features["imp_suspicious_api_ratio"] = 0.0

        return features

    def _extract_export_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract export-related features"""
        features = {
            "exp_num_functions": 0,
        }

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features["exp_num_functions"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

        return features

    def _extract_resource_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract resource-related features"""
        features = {
            "res_num_resources": 0,
            "res_total_size": 0,
            "res_avg_entropy": 0.0,
            "res_max_entropy": 0.0,
            "has_tls_callbacks": 0,
            "num_tls_callbacks": 0,
        }

        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return features

        entropies = []

        def count_resources(resource_entry, depth=0):
            if hasattr(resource_entry, 'directory'):
                for entry in resource_entry.directory.entries:
                    count_resources(entry, depth + 1)
            elif hasattr(resource_entry, 'data'):
                features["res_num_resources"] += 1
                try:
                    res_data = pe.get_data(
                        resource_entry.data.struct.OffsetToData,
                        resource_entry.data.struct.Size
                    )
                    features["res_total_size"] += len(res_data)
                    entropy = self.calculate_entropy(res_data)
                    entropies.append(entropy)
                except Exception:
                    pass

        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            count_resources(entry)

        if entropies:
            features["res_avg_entropy"] = round(sum(entropies) / len(entropies), 4)
            features["res_max_entropy"] = round(max(entropies), 4)

        # TLS callbacks
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
                features["has_tls_callbacks"] = 1
                try:
                    callbacks_addr = getattr(pe.DIRECTORY_ENTRY_TLS.struct, 'AddressOfCallBacks', 0)
                    # Count not straightforward; set to 1 if present
                    features["num_tls_callbacks"] = 1 if callbacks_addr else 0
                except Exception:
                    features["num_tls_callbacks"] = 0
            else:
                features["has_tls_callbacks"] = 0
                features["num_tls_callbacks"] = 0
        except Exception:
            features["has_tls_callbacks"] = 0
            features["num_tls_callbacks"] = 0

        return features

    def _extract_dll_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract DLL-specific features for ML"""
        features = {}

        features["dll_is_dll"] = 1 if pe.is_dll() else 0

        if not pe.is_dll():
            # Return default DLL features for non-DLL files
            features.update({
                "dll_char_aslr": 0,
                "dll_char_dep": 0,
                "dll_char_cfg": 0,
                "dll_char_high_entropy": 0,
                "dll_char_no_seh": 0,
                "dll_char_force_integrity": 0,
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
            })
            return features

        # DLL Characteristics features
        try:
            dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
            features["dll_char_aslr"] = 1 if dll_char & 0x0040 else 0
            features["dll_char_dep"] = 1 if dll_char & 0x0100 else 0
            features["dll_char_cfg"] = 1 if dll_char & 0x4000 else 0
            features["dll_char_high_entropy"] = 1 if dll_char & 0x0020 else 0
            features["dll_char_no_seh"] = 1 if dll_char & 0x0400 else 0
            features["dll_char_force_integrity"] = 1 if dll_char & 0x0080 else 0

            # Calculate security score
            features["dll_security_score"] = (
                features["dll_char_aslr"] * 25 +
                features["dll_char_dep"] * 25 +
                features["dll_char_cfg"] * 25 +
                features["dll_char_high_entropy"] * 15 +
                features["dll_char_force_integrity"] * 10
            )
        except Exception:
            features["dll_char_aslr"] = 0
            features["dll_char_dep"] = 0
            features["dll_char_cfg"] = 0
            features["dll_char_high_entropy"] = 0
            features["dll_char_no_seh"] = 0
            features["dll_char_force_integrity"] = 0
            features["dll_security_score"] = 0

        # Export features
        try:
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

                # DLL type indicators
                features["dll_is_com"] = 1 if com_count >= 2 else 0
                features["dll_is_proxy"] = 1 if features.get("dll_export_forwarded_ratio", 0) > 0.5 else 0
                features["dll_has_exports"] = 1 if len(exports) > 0 else 0
            else:
                features["dll_export_count"] = 0
                features["dll_export_named_count"] = 0
                features["dll_export_ordinal_only_count"] = 0
                features["dll_export_forwarded_count"] = 0
                features["dll_export_forwarded_ratio"] = 0.0
                features["dll_export_ordinal_ratio"] = 0.0
                features["dll_suspicious_export_count"] = 0
                features["dll_rundll_export_count"] = 0
                features["dll_com_export_count"] = 0
                features["dll_is_com"] = 0
                features["dll_is_proxy"] = 0
                features["dll_has_exports"] = 0
        except Exception:
            features["dll_export_count"] = 0
            features["dll_export_named_count"] = 0
            features["dll_export_ordinal_only_count"] = 0
            features["dll_export_forwarded_count"] = 0
            features["dll_export_forwarded_ratio"] = 0.0
            features["dll_export_ordinal_ratio"] = 0.0
            features["dll_suspicious_export_count"] = 0
            features["dll_rundll_export_count"] = 0
            features["dll_com_export_count"] = 0
            features["dll_is_com"] = 0
            features["dll_is_proxy"] = 0
            features["dll_has_exports"] = 0

        return features

    def _extract_data_directory_features(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract data directory presence features"""
        data_dirs = [
            "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
            "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
            "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT",
            "COM_DESCRIPTOR", "RESERVED"
        ]

        features = {}

        for i, dir_name in enumerate(data_dirs):
            try:
                entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
                features[f"dd_{dir_name.lower()}_present"] = 1 if entry.VirtualAddress != 0 else 0
                features[f"dd_{dir_name.lower()}_size"] = entry.Size
            except (IndexError, AttributeError):
                features[f"dd_{dir_name.lower()}_present"] = 0
                features[f"dd_{dir_name.lower()}_size"] = 0

        return features

    def get_feature_names(self) -> List[str]:
        """Get list of all feature names in order"""
        # Create a dummy feature dict to get all keys
        # This is useful for creating CSV headers
        feature_names = [
            # File features
            "file_size", "file_entropy", "file_entropy_high", "file_entropy_packed",
            "overlay_size", "timestamp", "timestamp_zero", "timestamp_age_days", "file_mtime_mismatch", "has_cert",
            # Hashes / magic
            "md5", "sha1", "sha256", "magic_bytes",
            # DOS header
            "dos_e_magic", "dos_e_lfanew",
            # File header
            "fh_machine", "fh_num_sections", "fh_timestamp", "fh_ptr_symbol_table",
            "fh_num_symbols", "fh_size_opt_header", "fh_characteristics",
            "fh_char_relocs_stripped", "fh_char_executable", "fh_char_large_address",
            "fh_char_32bit", "fh_char_debug_stripped", "fh_char_dll",
            # Optional header
            "oh_magic", "oh_major_linker_ver", "oh_minor_linker_ver",
            "oh_size_of_code", "oh_size_of_init_data", "oh_size_of_uninit_data",
            "oh_entry_point", "oh_base_of_code", "oh_image_base",
            "oh_section_alignment", "oh_file_alignment", "oh_major_os_ver",
            "oh_minor_os_ver", "oh_major_image_ver", "oh_minor_image_ver",
            "oh_major_subsystem_ver", "oh_minor_subsystem_ver", "oh_size_of_image",
            "oh_size_of_headers", "oh_checksum", "oh_subsystem", "oh_dll_characteristics",
            "oh_size_stack_reserve", "oh_size_stack_commit", "oh_size_heap_reserve",
            "oh_size_heap_commit", "oh_num_rva_sizes",
            "oh_dll_char_dynamic_base", "oh_dll_char_force_integrity", "oh_dll_char_nx_compat",
            "oh_dll_char_no_isolation", "oh_dll_char_no_seh", "oh_dll_char_no_bind",
            "oh_dll_char_wdm_driver", "oh_dll_char_terminal_server",
            "is_exe", "is_dll", "is_driver",
            # Section features
            "sec_num_sections", "sec_total_entropy", "sec_avg_entropy",
            "sec_max_entropy", "sec_min_entropy", "sec_total_raw_size",
            "sec_total_virtual_size", "sec_num_executable", "sec_num_writable",
            "sec_num_readable", "sec_num_code", "sec_num_data",
            "sec_num_suspicious_entropy", "sec_num_wx", "sec_size_mismatch_count",
            "sec_name_suspicious_count", "sec_virtual_vs_raw_ratio_max", "sec_virtual_vs_raw_ratio_avg", "sec_unmapped_entry_point",
            # Import features
            "imp_num_dlls", "imp_num_functions", "imp_avg_functions_per_dll",
            "imp_by_ordinal_count", "imp_thunk_count", "imp_unusual_dlls_count", "imp_delay_import_count", "imp_suspicious_api_ratio",
            "imp_sus_process_injection", "imp_sus_keylogging", "imp_sus_anti_debugging",
            "imp_sus_network", "imp_sus_registry", "imp_sus_file_operations",
            "imp_sus_persistence", "imp_sus_crypto", "imp_sus_anti_vm", "imp_sus_total",
            # Export features
            "exp_num_functions",
            # Resource features
            "res_num_resources", "res_total_size", "res_avg_entropy", "res_max_entropy", "has_tls_callbacks", "num_tls_callbacks",
            # String/IOC features
            "extracted_strings_count", "extracted_strings_avg_len", "extracted_strings_max_len", "res_string_url_count", "res_string_ip_count", "suspicious_string_patterns_count", "res_string_email_count", "res_string_path_count", "res_string_base64_count",
            # Statistical
            "printable_ratio", "byte_stddev",
            # Code/data
            "sec_code_data_ratio",
            # Version
            "has_version_info", "version_string_count",
            # Behavioral booleans
            "has_anti_debugging", "has_injection_apis", "has_network_apis", "has_filesystem_apis", "has_persistence_apis",
            # Data directory features
            "dd_export_present", "dd_export_size", "dd_import_present", "dd_import_size",
            "dd_resource_present", "dd_resource_size", "dd_exception_present", "dd_exception_size",
            "dd_security_present", "dd_security_size", "dd_basereloc_present", "dd_basereloc_size",
            "dd_debug_present", "dd_debug_size", "dd_architecture_present", "dd_architecture_size",
            "dd_globalptr_present", "dd_globalptr_size", "dd_tls_present", "dd_tls_size",
            "dd_load_config_present", "dd_load_config_size", "dd_bound_import_present",
            "dd_bound_import_size", "dd_iat_present", "dd_iat_size",
            "dd_delay_import_present", "dd_delay_import_size",
            "dd_com_descriptor_present", "dd_com_descriptor_size",
            "dd_reserved_present", "dd_reserved_size",
            # DLL-specific features
            "dll_char_aslr", "dll_char_dep", "dll_char_cfg", "dll_char_high_entropy",
            "dll_char_no_seh", "dll_char_force_integrity", "dll_security_score",
            "dll_export_count", "dll_export_named_count", "dll_export_ordinal_only_count",
            "dll_export_forwarded_count", "dll_export_forwarded_ratio", "dll_export_ordinal_ratio",
            "dll_suspicious_export_count", "dll_rundll_export_count", "dll_com_export_count",
            "dll_is_com", "dll_is_proxy", "dll_has_exports",
        ]
        return feature_names
