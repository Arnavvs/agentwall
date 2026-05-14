#!/bin/bash
set -e

echo "Building AgentWheel..."
uv build
echo "Build complete. Wheel in dist/"
ls -la dist/
