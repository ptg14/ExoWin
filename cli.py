"""
CLI interface for ExoWin - Simplified version
"""
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from exowin.analyzer import ExoWinAnalyzer
from exowin.reporters import (
    JSONReporter,
    HTMLReporter,
    MarkdownReporter,
    ConsoleReporter,
    CSVReporter,
)
from exowin.extractors import MLFeaturesExtractor

app = typer.Typer(
    name="exowin",
    help="ExoWin - Static analysis and feature extraction for PE files (EXE/DLL)",
    add_completion=False,
)

console = Console()

# Initialize analyzer and reporters
analyzer = ExoWinAnalyzer()
reporters = {
    "json": JSONReporter(),
    "html": HTMLReporter(),
    "markdown": MarkdownReporter(),
    "md": MarkdownReporter(),
    "console": ConsoleReporter(),
    "csv": CSVReporter(),
}

# ML Feature extractor
ml_extractor = MLFeaturesExtractor()


def _detect_pe_type(pe) -> str:
    """Detect PE type (EXE or DLL)"""
    return "DLL" if pe.is_dll() else "EXE"


def _get_pe_files(path: Path, recursive: bool = False) -> list:
    """Get all PE files from path (file or directory)"""
    # Resolve to absolute path
    path = path.resolve()

    if path.is_file():
        return [path]
    elif path.is_dir():
        patterns = ["*.exe", "*.dll", "*.EXE", "*.DLL"]
        files = []
        for pattern in patterns:
            if recursive:
                files.extend(path.rglob(pattern))
            else:
                files.extend(path.glob(pattern))
        return list(set(files))  # Remove duplicates
    return []


def _analyze_single_file(filepath: Path, include_disasm: bool = False) -> dict:
    """Analyze a single PE file with auto DLL detection"""
    import pefile
    from exowin.extractors import DLLFeaturesExtractor

    result = analyzer.analyze_file(str(filepath), include_disasm=include_disasm)

    # Auto-detect and add DLL features
    try:
        pe = pefile.PE(str(filepath))
        if pe.is_dll():
            dll_extractor = DLLFeaturesExtractor()
            result["dll_features"] = dll_extractor.extract(pe, str(filepath))
        pe.close()
    except Exception:
        pass

    return result


def _extract_features_single(filepath: Path, label: Optional[str] = None) -> dict:
    """Extract ML features from a single PE file (unified EXE/DLL extraction)"""
    import pefile

    pe = pefile.PE(str(filepath))
    # Base extractor already includes all features (EXE + DLL)
    features = ml_extractor.extract(pe, str(filepath))

    # Add metadata
    is_dll = pe.is_dll()
    features["filename"] = filepath.name
    features["pe_type"] = "DLL" if is_dll else "EXE"
    if label:
        features["label"] = label

    pe.close()
    return features


@app.command()
def gui():
    """
    Launch the graphical user interface
    """
    try:
        from exowin.gui import main as gui_main
        console.print("[blue]Launching GUI...[/blue]")
        gui_main()
    except ImportError as e:
        console.print(f"[red]Error launching GUI: {e}[/red]")
        console.print("[yellow]Make sure customtkinter is installed[/yellow]")
        raise typer.Exit(1)


@app.command()
def analyze(
    path: Path = typer.Argument(..., help="Path to PE file or directory"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file/directory path"),
    format: str = typer.Option("console", "--format", "-f", help="Output format: console, json, html, markdown"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Search subdirectories"),
    disasm: bool = typer.Option(False, "--disasm", "-d", help="Scan for suspicious disassembly patterns"),
):
    """
    Analyze PE file(s) - auto-detects file/folder, EXE/DLL
    """
    try:
        files = _get_pe_files(path, recursive)

        if not files:
            console.print(f"[red]No PE files found: {path}[/red]")
            raise typer.Exit(1)

        # Single file
        if len(files) == 1:
            filepath = files[0]
            console.print(f"[blue]Analyzing: {filepath.name}[/blue]")

            result = _analyze_single_file(filepath, include_disasm=disasm)

            # Detect type
            pe_type = result.get("headers", {}).get("pe_type", "PE")
            if "dll_features" in result:
                pe_type = "DLL"
            console.print(f"[cyan]Detected: {pe_type}[/cyan]")

            # Generate report
            # Auto-detect format from output file extension, or append extension from format
            actual_format = format
            output_file = output

            if output:
                ext = output.suffix.lower().lstrip('.')
                if ext in ["json", "html", "md", "markdown", "csv"]:
                    # Extension provided - auto-detect format if format is console
                    if format == "console":
                        actual_format = ext
                else:
                    # No extension - append extension from format
                    if format != "console":
                        ext_map = {"json": ".json", "html": ".html", "markdown": ".md", "md": ".md", "csv": ".csv"}
                        if format in ext_map:
                            output_file = Path(str(output) + ext_map[format])

            reporter = reporters.get(actual_format, ConsoleReporter())
            if output_file:
                output_path = str(output_file.resolve())
            else:
                output_path = None
            reporter.generate(result, output_path)

            if output_file:
                console.print(f"[green]Report saved: {output_file}[/green]")

        # Multiple files (directory)
        else:

            console.print(f"[blue]Found {len(files)} PE files[/blue]")

            # Create output directory if needed
            if output:
                output.mkdir(parents=True, exist_ok=True)

            success_count = 0
            failed_count = 0
            dll_count = 0
            exe_count = 0

            root_dir = path.resolve()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("Analyzing...", total=len(files))

                for filepath in files:
                    try:
                        result = _analyze_single_file(filepath, include_disasm=disasm)

                        # Count types
                        if "dll_features" in result:
                            dll_count += 1
                        else:
                            exe_count += 1

                        # Save report
                        if output:
                            ext = "md" if format == "markdown" else format
                            # Tạo tên file report có thêm tên thư mục nếu là file trong subfolder
                            rel_path = filepath.relative_to(root_dir)
                            rel_parts = rel_path.parts[:-1]  # các thư mục cha
                            if rel_parts:
                                prefix = "_".join(rel_parts) + "_"
                            else:
                                prefix = ""
                            report_name = prefix + filepath.stem + f".{ext}"
                            report_path = output / report_name
                            reporter = reporters.get(format, JSONReporter())
                            reporter.generate(result, str(report_path))

                        success_count += 1

                    except Exception as e:
                        failed_count += 1
                        console.print(f"[red]Error: {filepath.name} - {e}[/red]")

                    progress.update(task, advance=1)

            console.print(f"\n[bold]Results:[/bold]")
            console.print(f"[green]Success: {success_count}[/green] (EXE: {exe_count}, DLL: {dll_count})")
            console.print(f"[red]Failed: {failed_count}[/red]")
            if output:
                console.print(f"[blue]Reports saved to: {output}[/blue]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.command()
def compare(
    file1: Path = typer.Argument(..., help="First PE file"),
    file2: Path = typer.Argument(..., help="Second PE file"),
):
    """
    Compare two PE files
    """
    try:
        from rich.table import Table

        console.print(f"[blue]Comparing {file1.name} and {file2.name}[/blue]\n")

        # Analyze both files
        result1 = _analyze_single_file(file1)
        result2 = _analyze_single_file(file2)

        # Compare file info
        table = Table(title="File Information Comparison")
        table.add_column("Property", style="cyan")
        table.add_column(file1.name[:30], style="yellow")
        table.add_column(file2.name[:30], style="green")

        info1 = result1.get("file_info", {})
        info2 = result2.get("file_info", {})

        for prop in ["size", "md5", "entropy", "imphash"]:
            v1 = info1.get(prop, "N/A")
            v2 = info2.get(prop, "N/A")
            if isinstance(v1, float):
                v1 = f"{v1:.4f}"
            if isinstance(v2, float):
                v2 = f"{v2:.4f}"
            match = "✓" if v1 == v2 else "✗"
            table.add_row(f"{prop} {match}", str(v1), str(v2))

        console.print(table)

        # Compare PE type
        type1 = "DLL" if "dll_features" in result1 else "EXE"
        type2 = "DLL" if "dll_features" in result2 else "EXE"
        console.print(f"\n[bold]PE Types:[/bold] {file1.name}: {type1}, {file2.name}: {type2}")

        # Compare sections
        console.print("\n")
        sections_table = Table(title="Sections Comparison")
        sections_table.add_column("Section", style="cyan")
        sections_table.add_column(f"{file1.name[:20]} Entropy", style="yellow")
        sections_table.add_column(f"{file2.name[:20]} Entropy", style="green")
        sections_table.add_column("Status", style="magenta")

        s1_dict = {s["Name"]: s for s in result1.get("sections", {}).get("sections", [])}
        s2_dict = {s["Name"]: s for s in result2.get("sections", {}).get("sections", [])}
        all_sections = set(s1_dict.keys()) | set(s2_dict.keys())

        for section in sorted(all_sections):
            e1 = f"{s1_dict[section]['Entropy']:.2f}" if section in s1_dict else "-"
            e2 = f"{s2_dict[section]['Entropy']:.2f}" if section in s2_dict else "-"
            if section in s1_dict and section in s2_dict:
                status = "Both"
            elif section in s1_dict:
                status = f"Only {file1.name[:15]}"
            else:
                status = f"Only {file2.name[:15]}"
            sections_table.add_row(section, e1, e2, status)

        console.print(sections_table)

        # Compare suspicious indicators
        ind1 = set(result1.get("suspicious_indicators", []))
        ind2 = set(result2.get("suspicious_indicators", []))

        common = ind1 & ind2
        only1 = ind1 - ind2
        only2 = ind2 - ind1

        if common or only1 or only2:
            console.print("\n[bold]Suspicious Indicators:[/bold]")
            if common:
                console.print(f"[yellow]Common ({len(common)}):[/yellow]")
                for ind in list(common)[:5]:
                    console.print(f"  - {ind}")
            if only1:
                console.print(f"\n[red]Only in {file1.name} ({len(only1)}):[/red]")
                for ind in list(only1)[:5]:
                    console.print(f"  - {ind}")
            if only2:
                console.print(f"\n[green]Only in {file2.name} ({len(only2)}):[/green]")
                for ind in list(only2)[:5]:
                    console.print(f"  - {ind}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="extract-features")
def extract_features(
    path: Path = typer.Argument(..., help="Path to PE file or directory"),
    output: Path = typer.Argument(..., help="Output CSV file path"),
    label: Optional[str] = typer.Option(None, "--label", "-l", help="Label for samples"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Search subdirectories"),
    append: bool = typer.Option(False, "--append", "-a", help="Append to existing CSV"),
):
    """
    Extract ML features from PE file(s) - auto-detects file/folder, EXE/DLL
    """
    try:
        files = _get_pe_files(path, recursive)

        if not files:
            console.print(f"[red]No PE files found: {path}[/red]")
            raise typer.Exit(1)

        console.print(f"[blue]Found {len(files)} PE file(s)[/blue]")

        all_features = []
        success_count = 0
        failed_count = 0
        dll_count = 0
        exe_count = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Extracting features...", total=len(files))

            for filepath in files:
                try:
                    features = _extract_features_single(filepath, label)

                    if features.get("pe_type") == "DLL":
                        dll_count += 1
                    else:
                        exe_count += 1

                    all_features.append(features)
                    success_count += 1

                except Exception as e:
                    failed_count += 1
                    console.print(f"[red]Error: {filepath.name} - {e}[/red]")

                progress.update(task, advance=1)


        # Đảm bảo output có đuôi .csv
        output_path = output
        if output_path.suffix.lower() != ".csv":
            output_path = output_path.with_suffix(output_path.suffix + ".csv") if output_path.suffix else output_path.with_suffix(".csv")

        # Save to CSV
        if all_features:
            if append and output_path.exists():
                import csv
                with open(output_path, "a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=all_features[0].keys())
                    for features in all_features:
                        writer.writerow(features)
                console.print(f"[green]Features appended to: {output_path}[/green]")
            else:
                CSVReporter.generate_batch(all_features, str(output_path))
                console.print(f"[green]Features saved to: {output_path}[/green]")

        console.print(f"\n[bold]Results:[/bold]")
        console.print(f"[green]Success: {success_count}[/green] (EXE: {exe_count}, DLL: {dll_count})")
        console.print(f"[red]Failed: {failed_count}[/red]")
        console.print(f"[bold]Features per sample:[/bold] {len(all_features[0]) if all_features else 0}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.command(name="list-features")
def list_features():
    """
    List all available ML features (unified for EXE and DLL)
    """
    from rich.table import Table

    # All features from base extractor (already includes DLL features)
    all_features = ml_extractor.get_feature_names()

    table = Table(title="Available ML Features (Unified EXE/DLL)")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Feature Name", style="cyan")
    table.add_column("Category", style="yellow")

    for i, name in enumerate(all_features, 1):
        # Determine category
        if name.startswith("file_"):
            category = "File"
        elif name.startswith("dos_"):
            category = "DOS Header"
        elif name.startswith("fh_"):
            category = "File Header"
        elif name.startswith("oh_"):
            category = "Optional Header"
        elif name.startswith("sec_"):
            category = "Sections"
        elif name.startswith("imp_"):
            category = "Imports"
        elif name.startswith("exp_"):
            category = "Exports"
        elif name.startswith("res_"):
            category = "Resources"
        elif name.startswith("dd_"):
            category = "Data Directory"
        elif name.startswith("is_"):
            category = "PE Type"
        elif name.startswith("dll_"):
            category = "[magenta]DLL-Specific[/magenta]"
        else:
            category = "Other"
        table.add_row(str(i), name, category)

    console.print(table)
    console.print(f"\n[bold]Total features:[/bold] {len(all_features)}")
    console.print("[dim]Note: DLL features (dll_*) are extracted for all PE files. For EXE files, these values will be 0.[/dim]")


@app.command()
def version():
    """
    Display ExoWin version
    """
    from exowin import __version__
    console.print(f"[bold blue]ExoWin v{__version__}[/bold blue]")
    console.print("Static analysis and feature extraction for PE files (EXE/DLL)")
    console.print("\n[dim]Commands: gui, analyze, compare, extract-features, list-features[/dim]")


def main():
    app()


if __name__ == "__main__":
    main()
