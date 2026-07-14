#!/bin/bash
set -e
cd "$(dirname "$0")/Lara3-fixed"
exec bash ./ipabuild.sh "$@"
