#!/bin/bash
# Unipacker entrypoint script
# Supports CLI mode for single file unpacking

set -e

INPUT_FILE="$1"
OUTPUT_DIR="${2:-/workspace/output}"

# Handle help flag
if [ "$INPUT_FILE" = "--help" ] || [ "$INPUT_FILE" = "-h" ]; then
    echo "Unipacker Docker Container"
    echo "Usage: docker run unipacker <input_file> [output_dir]"
    echo ""
    echo "Arguments:"
    echo "  input_file   Path to packed PE binary"
    echo "  output_dir   Output directory (default: /workspace/output)"
    echo ""
    echo "Output: JSON with success, packer, output path, and OEP"
    exit 0
fi

if [ -z "$INPUT_FILE" ]; then
    echo "Usage: docker run unipacker <input_file> [output_dir]"
    exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file not found: $INPUT_FILE"
    exit 1
fi

# Get base filename for output
BASENAME=$(basename "$INPUT_FILE" | sed 's/\.[^.]*$//')
OUTPUT_FILE="${OUTPUT_DIR}/${BASENAME}_unpacked.exe"

# Run unipacker in non-interactive mode
# -d: destination file
# The unipacker will detect the packer and attempt to unpack
echo "{\"status\":\"starting\",\"input\":\"$INPUT_FILE\"}"

python3 -c "
import sys
import json
import os

try:
    from unipacker.unipacker import UnpackerClient
    from unipacker.core import Sample
    
    input_file = '$INPUT_FILE'
    output_file = '$OUTPUT_FILE'
    
    # Create sample and unpack
    sample = Sample(input_file)
    
    # Get detected packer info
    packer_name = sample.packer.__class__.__name__ if sample.packer else 'Unknown'
    
    # Run unpacking
    client = UnpackerClient(sample)
    client.unpack()
    
    # Get unpacked binary
    unpacked_data = sample.get_memory_mapped_image()
    
    if unpacked_data:
        with open(output_file, 'wb') as f:
            f.write(unpacked_data)
        
        result = {
            'success': True,
            'packer': packer_name,
            'input': input_file,
            'output': output_file,
            'original_size': os.path.getsize(input_file),
            'unpacked_size': len(unpacked_data),
            'oep': hex(sample.unpacker.current_oep) if hasattr(sample.unpacker, 'current_oep') else None
        }
    else:
        result = {
            'success': False,
            'packer': packer_name,
            'input': input_file,
            'error': 'Failed to extract unpacked image'
        }
    
    print(json.dumps(result))
    sys.exit(0 if result['success'] else 1)

except Exception as e:
    result = {
        'success': False,
        'input': '$INPUT_FILE',
        'error': str(e)
    }
    print(json.dumps(result))
    sys.exit(1)
"
