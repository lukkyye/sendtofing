#!/bin/bash

# Obtener el path del script actual
SCRIPT_PATH=$(dirname "$(realpath "$0")")

cd "$SCRIPT_PATH/.venv/bin/" && source activate
cd "$SCRIPT_PATH" && python3 main.py
