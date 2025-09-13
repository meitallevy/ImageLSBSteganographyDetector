import re
import sys
from enum import Enum

from PIL import Image

from analysis_reports import ExtractionReport, ExtractionReportCollectionForImage
from suspicious_patterns import DANGEROUS_FUNCTION_PATTERNS, ALL_CODE_PATTERNS


class ExtractionMode(Enum):
    R = 0
    G = 1
    B = 2
    INTERLEAVED = 3


BITS_IN_BYTE = 8


def extract_bytes_from_lsb(image_path, extraction_mode: ExtractionMode = ExtractionMode.INTERLEAVED):
    """
    Extract bytes from LSBs of an image.
    """
    image = Image.open(image_path).convert('RGB')
    pixels_rgb = list(image.getdata())

    extracted_bits = extract_lsb(extraction_mode, pixels_rgb)

    extracted_bytes = bytearray()
    for start_index in range(0, len(extracted_bits), BITS_IN_BYTE):
        byte_value = 0
        for bit_offset, bit in enumerate(extracted_bits[start_index:start_index + BITS_IN_BYTE]):
            byte_value |= bit << (BITS_IN_BYTE - 1 - bit_offset)
        if byte_value == 0:
            break  # padding
        extracted_bytes.append(byte_value)

    return bytes(extracted_bytes)


def extract_lsb(extraction_mode: ExtractionMode, pixels_rgb):
    """
    Extract LSBs depending on the mode.
    INTERLEAVED: R,G,B,R,G,B...
    Single channel: R or G or B only
    """
    extracted_bits = []

    if extraction_mode == ExtractionMode.INTERLEAVED:
        for r, g, b in pixels_rgb:
            extracted_bits.extend([r & 1, g & 1, b & 1])
    else:
        extracted_bits = [pixel[extraction_mode.value] & 1 for pixel in pixels_rgb]
    return extracted_bits


def extract_text(extracted_bytes):
    """
    Reconstruct full payload from extracted bytes.
    Stop at first null byte if present.
    """
    try:
        null_index = extracted_bytes.index(0)
        payload_bytes = extracted_bytes[:null_index]
    except ValueError:
        payload_bytes = extracted_bytes

    decoded_text = payload_bytes.decode('utf-8', errors='ignore')
    return decoded_text


def analyze_extracted_payload(payload_text, mode):
    report = ExtractionReport(mode)
    report.preview_text = payload_text
    report.code_matches = [
        pattern for pattern in ALL_CODE_PATTERNS if re.search(pattern, payload_text, re.MULTILINE)
    ]
    report.dangerous_function_matches = [
        pattern for pattern in DANGEROUS_FUNCTION_PATTERNS if re.search(pattern, payload_text)
    ]
    report.summarize()
    return report


def main():
    if len(sys.argv) < 2:
        print("Usage: python decode.py <image_path>")
        return None

    image_path = sys.argv[1]
    full_report = ExtractionReportCollectionForImage(image_path)

    for mode in ExtractionMode:
        extracted_bytes = extract_bytes_from_lsb(image_path, extraction_mode=mode)
        extracted_payload = extract_text(extracted_bytes)
        mode_report = analyze_extracted_payload(extracted_payload, mode)
        full_report.add_mode_report(mode_report)

    _print_report(full_report)
    return full_report


def _print_report(full_report: ExtractionReportCollectionForImage):
    print(f"Report for image: {full_report.image_path}\n")
    for mode_report in full_report.mode_reports:
        print(f"[Mode: {mode_report.extraction_mode.name}]")
        if mode_report.preview_text:
            print("Preview:", mode_report.preview_text[:500])
        if mode_report.is_suspicious:
            print("Suspicious patterns detected!")
            if mode_report.code_matches:
                print("Code indicators:", mode_report.code_matches)
            if mode_report.dangerous_function_matches:
                print("Dangerous functions:", mode_report.dangerous_function_matches)
        else:
            print("No suspicious patterns detected.")
        print("-" * 50)


if __name__ == '__main__':
    main()
