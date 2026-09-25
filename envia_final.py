import socket
import struct
import os
import sys
import time

FORMAT = "!BBHHH"

# Defining global variables

MAGIC_NIBBLE = 0x0B  # Magic number for control bytes

# Bit 7: packet is DATA or CONTROL
CTX_DATA = 0  # Data packet
CTX_CTRL = 1  # Control packet

# Bit 6: start or stop command
CMD_START = 0  # Start command
CMD_END = 1    # End command

# Bit 5: nibble
PART_HIGH = 0  # High nibble
PART_LOW = 1   # Low nibble

# Bit 5: Control
SUB_SIZE = 0       # File size
SUB_EXTENSION = 1  # File extension

# Update when containers are created
SOURCE      = "127.0.0.1"
DESTINATION = "127.0.0.1"

message = (
    b"\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037 !\"#$%&'()*+,-./01234567"
)
# Avoid congestion (menu to select)
DELAY_OPTIONS = {
    "1": ("No delay (fastest)",      0.000),
    "2": ("Fast (2ms)",              0.002),
    "3": ("Normal (5ms) RECOMMENDED",  0.005),
    "4": ("Slow (10ms)",             0.010),
    "5": ("Very slow (50ms)",        0.050),
    "6": ("Slowest (4s)",            4.000),
}


# Build data packets
def build_data_byte(seq_bit: int, part: int, nibble: int) -> int:
    # Parity is not passed by the program but calculated based on bits 3 to 0
    parity = bin(nibble).count("1") % 2
    # The data byte is built by setting CTX to 0, the bit sequence already calculated by another function, which nibble, parity calculated by this function using the nibble, and the actual nibble to be sent
    assembled_byte = (CTX_DATA << 7) | (seq_bit << 6) | (part << 5) | (parity << 4) | (nibble & 0x0F)
    return assembled_byte

# Build control packets
def build_control_byte(cmd: int, sub: int) -> int:
    # The control byte is built by setting CTX to 1, the command, the sub-command, setting 1 to prove it's valid, and the magic number or file ext/size
    assembled_byte = (CTX_CTRL << 7) | (cmd << 6) | (sub << 5) | (1 << 4) | (MAGIC_NIBBLE & 0x0F)
    return assembled_byte

# Packet creation + Checksum, original code only changes type from 8 to 0 because the spec requires using Reply instead of Request (request = 8, reply = 0)
def create_icmp(payload: bytearray, sequence: int) -> bytearray:
    type_field = 0
    code = 0
    checksum = 0

    # Sequence and ID use % 65536 because the ICMP H field only goes up to 65535; if exceeded, struct raises an error, so it wraps around and continues sending
    identifier = os.getpid() % 65536
    sequence = sequence % 65536

    header = struct.pack(FORMAT, type_field, code, checksum, identifier, sequence)

    packet = header + payload
    packet_length = len(packet)
    n = 2

    if packet_length % 2:
        packet += b"\x00"

    for i in range(0, packet_length, n):
        word = packet[i:i + n]
        checksum += int.from_bytes(word, byteorder="big")

    while checksum >> 16:
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = (~checksum) & 0xFFFF

    header = struct.pack(FORMAT, type_field, code, checksum, identifier, sequence)
    packet = header + payload
    return packet

# Places the byte in the payload and sends the packet
def send_packet(sock, modified_byte: int, icmp_seq: int) -> None:
    hidden_payload = bytearray(message)

    # Modifies only byte 0, leaves the others unchanged from the original
    hidden_payload[0] = modified_byte

    packet = create_icmp(hidden_payload, icmp_seq)

    sock.sendto(packet, (DESTINATION, 0))

EXTENSION_MAP = {
    "bin": 0x0, "jpg": 0x1, "jpeg": 0x1, "png": 0x2, "pdf": 0x3,
    "zip": 0x4, "txt": 0x5, "bmp": 0x6, "gif": 0x7, "mp3": 0x8,
    "wav": 0x9, "mp4": 0xA, "doc": 0xB, "py":  0xC, "tar": 0xD,
    "msg": 0xF,  # Special code for text messages
}

# Interactive menu for choosing what to send
print("=" * 50)
print("  Steganographed Messenger - Sender")
print("=" * 50)
print("[1] Send a text message")
print("[2] Send a file")
print("=" * 50)

choice = input("Select an option (1/2): ").strip()

if choice == "1":
    # Text message mode: user types the message directly in the CLI
    text_message = input("Type your message: ")
    file_data = text_message.encode("utf-8")
    file_size = len(file_data)
    extension = "msg"
    extension_code = EXTENSION_MAP["msg"]

    print(f"\nStarting message transmission")
    print(f"Message: {text_message}")
    print(f"Size: {file_size} bytes")
    print(f"Destination: {DESTINATION}")
    print(f"{file_size * 2} DATA packets")

elif choice == "2":
    # File mode: user provides the file path via CLI argument or input
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Enter the file path: ").strip()

    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)

    # rb opens in raw binary mode without text encoding so that bytes are handled correctly
    with open(file_path, "rb") as f:
        file_data = f.read()

    file_size = len(file_data)

    # Getting the file extension and removing the dot
    extension = os.path.splitext(file_path)[1].lstrip(".")
    extension_code = EXTENSION_MAP.get(extension.lower(), 0x0)  # Default: binary

    print(f"\nStarting file transmission")
    print(f"File: {file_path}")
    print(f"Size: {file_size} bytes")
    print(f"Extension: {extension} (code: 0x{extension_code:X})")
    print(f"Destination: {DESTINATION}")
    print(f"{file_size * 2} DATA packets")

else:
    print("Invalid option. Exiting.")
    sys.exit(1)

# Speed selection menu
print("\n" + "=" * 50)
print("  Select transmission speed")
print("=" * 50)
for key, (label, _) in DELAY_OPTIONS.items():
    print(f"[{key}] {label}")
print("=" * 50)

speed_choice = input("Select speed (1-6) [default: 3]: ").strip()
if speed_choice not in DELAY_OPTIONS:
    speed_choice = "3"  # Default: Normal (5ms)

delay_label, DELAY_BETWEEN_PACKETS = DELAY_OPTIONS[speed_choice]
print(f"Speed selected: {delay_label}\n")

# Sent packet counter
packet_count = 0

# Actual start of communication
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
    s.bind((SOURCE, 0))

    print("\nStarting the first phase of data transmission, sending START and metadata")

    # To support larger files up to 16MB, instead of sending only 2 nibbles for the file size, 6 nibbles are sent to compose the file size
    size_nibbles = []
    temp_size = file_size
    for i in range(6):
        # Getting only the lowest 4 bits and shifting to get the others later
        size_nibbles.append(temp_size & 0x0F)
        temp_size >>= 4
    size_nibbles.reverse()  # Reverse the bits to get the correct order

    # Sending the first control byte for size and defining the file size
    for size_nibble in size_nibbles:
        ctrl_byte = build_control_byte(CMD_START, SUB_SIZE)
        # Replaces bits 7 to 4 with those generated by the byte builder function and bits 3 to 0 with the size nibble
        ctrl_byte = (ctrl_byte & 0xF0) | (size_nibble & 0x0F)
        packet_count += 1
        send_packet(s, ctrl_byte, packet_count)
        time.sleep(DELAY_BETWEEN_PACKETS)

    print(f"Total size from 6 nibbles sent: {file_size}")

    # Sending the second START and defining the file extension, similar to above but with the extension instead of the size
    ext_byte = build_control_byte(CMD_START, SUB_EXTENSION)
    # Replaces bits 7 to 4 with those generated by the byte builder function and bits 3 to 0 with the file extension code
    ext_byte = (ext_byte & 0xF0) | (extension_code & 0x0F)
    packet_count += 1
    send_packet(s, ext_byte, packet_count)
    time.sleep(DELAY_BETWEEN_PACKETS)

    print(f"Extension {extension} sent as code 0x{extension_code:x}")

    # Sending the actual file data
    print(f"\nSending {file_size} bytes of file data")

    # Creating the sequence variable starting at 0
    seq_bit = 0

    # Calculating for progress prints
    step_10_percent = max(1, file_size // 10)

    # Iterating over all bytes of the read file and sending them nibble by nibble
    for byte_index, file_byte in enumerate(file_data):
        # Getting the 4 most significant bits (7 to 4) and shifting them to bits 3 to 0 position ("clearing the beginning")
        high_nibble = (file_byte >> 4) & 0X0F
        # Using the already created function to build the data packet
        byte_high = build_data_byte(seq_bit, PART_HIGH, high_nibble)
        packet_count += 1
        send_packet(s, byte_high, packet_count)
        time.sleep(DELAY_BETWEEN_PACKETS)

        # Same as above but for the low nibbles
        # Clearing the beginning to keep only bits 3 to 0; no shift needed because they are already in the correct position
        low_nibble = file_byte & 0x0F
        # Using the already created function to build the data packet
        byte_low = build_data_byte(seq_bit, PART_LOW, low_nibble)
        packet_count += 1
        send_packet(s, byte_low, packet_count)
        time.sleep(DELAY_BETWEEN_PACKETS)

        # Using XOR to toggle from 1 to 0 and from 0 to 1
        seq_bit ^= 1

        # Progress prints every 10%
        bytes_sent = byte_index + 1
        is_done = (bytes_sent == file_size)

        # Print transmission progress every 10%
        if (bytes_sent % step_10_percent == 0) or is_done:
            percentage = (bytes_sent / file_size) * 100
            print(f"{bytes_sent}/{file_size} bytes sent: {percentage:.2f}% completed")

    print("Final step: Sending end-of-transmission command to the receiver")

    byte_end = build_control_byte(CMD_END, 0)
    packet_count += 1
    send_packet(s, byte_end, packet_count)

    print("End packet sent successfully")
    print("Transmission completed")
