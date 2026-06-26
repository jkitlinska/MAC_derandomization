# src/visualization/file_output.py
import os
from typing import Iterable, Optional


def save_txt_report(
    lines: Iterable[str],
    input_dir: str,
    field_name: Optional[str],
    out_dir: str = ".",
) -> str:
    """
    Saves rows containing results to a text file.

    File name: dataset_<dataset-name>-<field-name>.txt

    Returns the full path to the file.
    """
    dataset_name = os.path.basename(os.path.normpath(input_dir)) or "root"
    safe_field = field_name or "NO_FIELD"

    # filename = f"dataset_{dataset_name}-{safe_field}.txt"
    filename = field_name if field_name else f"dataset_{dataset_name}.txt" # only for fingerprint analysis
    os.makedirs(out_dir, exist_ok=True)
    output_path = os.path.join(out_dir, filename)

    with open(output_path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(str(line) + "\n")

    return output_path
