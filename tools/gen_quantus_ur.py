import sys
try:
    from ur.ur_encoder import UREncoder
    from ur.ur import UR
except ImportError:
    print("Please install the 'ur' package: pip install ur")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 gen_quantus_ur.py <hex_data>")
        print("Example: python3 gen_quantus_ur.py 12345678")
        sys.exit(1)

    hex_data = sys.argv[1]
    
    # 1. Convert hex to bytes
    try:
        data = bytes.fromhex(hex_data)
    except ValueError:
        print("Error: Invalid hex string")
        sys.exit(1)

    # 2. Create UR for "bytes" type (which is what we mapped internally)
    # The firmware expects the payload to be structured as ur:bytes, 
    # but we want the prefix to be ur:quantus-sign-request
    
    # "bytes" type in UR registry
    ur = UR("bytes", data)
    encoder = UREncoder(ur, None)
    
    # 3. Get the encoded string
    part = next(encoder.encode())
    
    # 4. Replace the type
    # The library generates "ur:bytes/...", we want "ur:quantus-sign-request/..."
    quantus_ur = part.replace("ur:bytes", "ur:quantus-sign-request", 1)
    
    print("\nUR String:")
    print(quantus_ur)
    
    print("\nTo generate QR code in terminal (cargo install qrrs):")
    print(f"qrrs \"{quantus_ur}\"")

if __name__ == "__main__":
    main()

