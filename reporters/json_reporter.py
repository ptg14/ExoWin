"""
JSON reporter
"""
import json
from pathlib import Path
from typing import Any, Dict

from exowin.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """Generate JSON reports"""

    def generate(self, analysis_result: Dict[str, Any], output_path: str = None) -> str:
        """Generate JSON report with optimized disasm data"""
        # Create a copy to modify
        result = analysis_result.copy()

        # Optimize disasm section - use grouped format, remove full suspicious list
        if "disasm" in result and result["disasm"]:
            disasm = result["disasm"].copy()
            # Remove the full suspicious list (use grouped instead)
            if "suspicious" in disasm:
                del disasm["suspicious"]
            # Remove full instructions list to save space
            if "instructions" in disasm:
                del disasm["instructions"]
            result["disasm"] = disasm

        # Convert to JSON string
        json_str = json.dumps(result, indent=2, ensure_ascii=False)

        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)

        return json_str
