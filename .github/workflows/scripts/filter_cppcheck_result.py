#!/usr/bin/env python3
import argparse
import bisect
import csv
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


def get_changed_ranges(file_path, git_diff_range):
    """Get changed line ranges for a file"""
    try:
        cmd = f"git diff -U0 {git_diff_range} -- {file_path}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)

        ranges = []
        for line in result.stdout.split("\n"):
            if line.startswith("@@"):
                match = re.search(r"\+(\d+)(?:,(\d+))?", line)
                if match:
                    start = int(match.group(1))
                    count = int(match.group(2)) if match.group(2) else 1
                    if count > 0:
                        ranges.append((start, start + count - 1))
        return ranges
    except Exception as e:
        print(f"Error getting changed lines for {file_path}: {e}")
        return []


def is_line_in_ranges(line_num, ranges):
    """Check if line number is in any of the ranges"""
    if len(ranges) <= 5:  # Linear search for small number of ranges
        return any(start <= line_num <= end for start, end in ranges)

    # Binary search for larger number of ranges
    # Sort ranges by start position
    sorted_ranges = sorted(ranges)
    # Find insertion point
    idx = bisect.bisect_left(sorted_ranges, (line_num, line_num))

    # Check range at idx and idx-1
    for i in [idx - 1, idx]:
        if 0 <= i < len(sorted_ranges):
            start, end = sorted_ranges[i]
            if start <= line_num <= end:
                return True
    return False


def filter_cppcheck_results(xml_file, git_diff_range, output_file, max_size=None):
    """Filter cppcheck XML results to only include changed lines"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        filtered_errors = []
        file_ranges_cache = {}

        for error in root.findall(".//error"):
            error_id = error.get("id", "")
            if not error_id.startswith("misra-c2012"):
                continue

            for location in error.findall("location"):
                file_path = location.get("file")
                line_num = int(location.get("line", 0))

                if file_path and line_num > 0:
                    if file_path not in file_ranges_cache:
                        file_ranges_cache[file_path] = get_changed_ranges(
                            file_path, git_diff_range
                        )

                    ranges = file_ranges_cache[file_path]
                    if is_line_in_ranges(line_num, ranges):
                        filtered_errors.append(error)
                        break

        # Write CSV results
        with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["misra-c2012-rule", "severity", "file", "line", "column"])

            for error in filtered_errors:
                error_id = error.get("id", "").replace("misra-c2012-", "")
                severity = error.get("severity", "")

                for location in error.findall("location"):
                    file_path = location.get("file", "")
                    line_num = location.get("line", "")
                    column = location.get("column", "")
                    row_size = len(
                        f"{error_id},{severity},{file_path},{line_num},{column}\n"
                    )
                    if max_size and csvfile.tell() + row_size > max_size:
                        print(f"Output file size limit ({max_size} bytes) reached")
                        break
                    writer.writerow([error_id, severity, file_path, line_num, column])

        print(f"Found {len(filtered_errors)} issues in changed lines")

        # Also print human-readable format
        for error in filtered_errors:
            severity = error.get("severity", "unknown")
            msg = error.get("msg", "")
            error_id = error.get("id", "")

            for location in error.findall("location"):
                file_path = location.get("file")
                line_num = location.get("line")
                print(f"{file_path}:{line_num}: {severity}: {msg} [{error_id}]")

        return len(filtered_errors)

    except Exception as e:
        print(f"Error filtering results: {e}")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Filter cppcheck results for MISRA violations in changed lines"
    )
    parser.add_argument("--input", required=True, help="Path to cppcheck XML file")
    parser.add_argument(
        "--output", required=True, help="Output CSV for filtered results file path"
    )
    parser.add_argument(
        "--git-diff",
        default="origin/main...HEAD",
        help="Git diff range (default: origin/main...HEAD)",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        help="Maximum output file size in bytes",
    )

    args = parser.parse_args()
    num_issues = filter_cppcheck_results(
        args.input, args.git_diff, args.output, args.max_size
    )
    print(f"Found {num_issues} misra violations")
    sys.exit(0)
