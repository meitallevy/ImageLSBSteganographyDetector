# Stego Detector

A Python tool for **extracting and analyzing hidden payloads** from images using The Least Significant Bit (LSB) steganography. Designed to detect **suspicious Python and JavaScript code** hidden in images, along with potentially dangerous functions.

---

## Features

- Extracts hidden bytes from images (PNG, JPEG, etc.) via **LSB steganography**.
- Supports multiple extraction modes:
  - `R` – Red channel
  - `G` – Green channel
  - `B` – Blue channel
  - `INTERLEAVED` – R, G, B in sequence
- Detects **Python code** patterns (`def`, `import`, `print`, etc.).
- Detects **JavaScript code** patterns (`function`, `eval`, `document.write`, etc.).
- Flags **dangerous functions** for both languages (`eval`, `os.system`, `open` in write mode, etc.).
---

## Installation

```bash
pip install -r requirements.txt
```
---

## Dependencies:

Pillow - for image processing
Stegano - for encoding

---
## Usage
Decoding:
```commandline
python3 decode.py /path/to/stego_image_stego.png
```

Output example:
```
Report for image: /path/to/stego_image_stego.png

[Mode: R]
Preview: fR2:/'
No suspicious patterns detected.
--------------------------------------------------
[Mode: G]
Preview: 01ya
No suspicious patterns detected.
--------------------------------------------------
[Mode: B]
Preview: Ǉ
No suspicious patterns detected.
--------------------------------------------------
[Mode: INTERLEAVED]
Preview: 23:print('I am malicious moohaha!').o!')'C)B"?
Suspicious patterns detected!
Code indicators: ['\\bprint\\s*\\(']
--------------------------------------------------
```
Encoding (for testing purposes):
```commandline
python3 encode.py stego_image.png
```
