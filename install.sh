#!/bin/bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
sudo apt update
sudo apt install -y mingw-w64
