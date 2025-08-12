#!/bin/bash

echo "|Field|Column|"
echo "|-|-|"
jq -r -f "$(realpath $0)/schema_paths.jq" "$1"| sed 's|.\[\].|\[\].|g'