#!/bin/bash
# Script to run cppcheck only on changed lines
COMMIT_BASE="origin/main"
COMMIT_TARGET="HEAD"
OUTPUT_FILE="cppcheck-full.xml"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --commit-base)
            COMMIT_BASE="$2"
            shift 2
            ;;
        --commit-target)
            COMMIT_TARGET="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--commit-base <base>] [--commit-target <target>] [--output <file>]"
            exit 1
            ;;
    esac
done

# Get changed files
CHANGED_FILES=$(git diff --name-only $COMMIT_BASE...$COMMIT_TARGET | grep -E '\.(c|cpp|cc|cxx|h|hpp)$')

if [ -z "$CHANGED_FILES" ]; then
    echo "No C/C++ files changed"
    exit 0
fi

# Run cppcheck on changed files
cppcheck --addon=misra --enable=all,style,warning,performance,portability,information,unusedFunction,missingInclude --suppressions-list="$(dirname "$0")/cppcheck_misra.config" --inline-suppr --language=c --std=c89 --xml --xml-version=2 $CHANGED_FILES 2> "$OUTPUT_FILE"
