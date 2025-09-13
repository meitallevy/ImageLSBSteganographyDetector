import sys
from pathlib import Path

from stegano import lsb

if len(sys.argv) != 2:
    print("Usage: python3 encode.py /path/to/image")
else:
    input_image = sys.argv[1]
    hidden_image = lsb.hide(input_image, "print('I am malicious moohaha!!!')")
    input_image_path = Path(sys.argv[1])
    new_path = f"{input_image_path.stem}_stego{input_image_path.suffix}"
    hidden_image.save(new_path)
    eval(lsb.reveal(new_path))
