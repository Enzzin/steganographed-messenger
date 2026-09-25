import socket
import struct
import sys

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
SOURCE = "127.0.0.1"

# Map to retrieve the extension from the code
EXTENSION_MAP = {
    0x0: "bin", 0x1: "jpg", 0x2: "png", 0x3: "pdf",
    0x4: "zip", 0x5: "txt", 0x6: "bmp", 0x7: "gif",
    0x8: "mp3", 0x9: "wav", 0xA: "mp4", 0xB: "doc",
    0xC: "py",  0xD: "tar", 0xF: "msg",  # "msg" = text message
}

def decode_byte(stego_byte: int) -> dict:
    # Extracts each bit using shift >> and uses & 1 to get only the correct bit in case of communication error
    ctx = (stego_byte >> 7) & 1
    seq_cmd = (stego_byte >> 6) & 1
    part_sub = (stego_byte >> 5) & 1
    parity = (stego_byte >> 4) & 1
    nibble = stego_byte & 0x0F

    return {
        "ctx": ctx,
        "seq_cmd": seq_cmd,
        "part_sub": part_sub,
        "parity": parity,
        "nibble": nibble,
    }

def validate_parity(nibble: int, parity_bit: int) -> bool:
    expected_parity = bin(nibble).count("1") % 2
    if expected_parity != parity_bit:
        return 0
    else:
        return 1

print(f"Listening on {SOURCE} and waiting for packets")

# Setting initial flags
receiving = False
file_buffer = bytearray()
temp_high_nibble = None
expected_size = 0
file_extension = "bin"
expected_seq = 0

# Storing the 6 nibbles of the file size
size_nibbles = []
receiving_size = False

# Packet counter for control
data_packets = 0
ignored_packets = 0

# Actual start of communication
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
    s.bind((SOURCE, 0))

    while True:
        # Receives data from the raw socket (packet with IP header + ICMP + payload)
        data, address = s.recvfrom(1024)

        # Unpacks the ICMP header starting at byte 20 after the 20-byte IP header
        type_field, code, checksum, _id, seq = struct.unpack(FORMAT, data[20:28])

        # Filters only ICMP Echo Reply packets (type 0), ignores other types like request (type 8)
        if type_field != 0:
            continue

        # Ensures the packet has at least 29 bytes (20 IP + 8 ICMP header + 1 modified payload byte)
        if len(data) < 29:
            continue

        # Gets only the first byte of the payload where the hidden data is
        stego_byte = data[28]

        # Decodes the bits of the received byte
        fields = decode_byte(stego_byte)
        ctx      = fields["ctx"]
        seq_cmd  = fields["seq_cmd"]
        part_sub = fields["part_sub"]
        parity   = fields["parity"]
        nibble   = fields["nibble"]

        # If it's a CONTROL packet (Bit 7 == 1)
        if ctx == CTX_CTRL:

            # In control packets, the validation bit (bit 4) must be fixed at 1 to confirm it's ours
            if parity != 1:
                ignored_packets += 1
                continue

            # START command (beginning of transmission)
            if seq_cmd == CMD_START:

                # Receiving the file size (size sub-command)
                if part_sub == SUB_SIZE and len(size_nibbles) < 6:
                    if not receiving_size and not receiving:
                        receiving_size = True
                        size_nibbles = []
                        file_buffer = bytearray()
                        temp_high_nibble = None
                        expected_seq = 0
                        data_packets = 0
                        print("\nSTART packet received - Initiating session")

                    # Accumulates the size nibble
                    if receiving_size:
                        size_nibbles.append(nibble)

                        # When all 6 nibbles are gathered, reassemble the total file size
                        if len(size_nibbles) == 6:
                            expected_size = 0
                            for nib in size_nibbles:
                                expected_size = (expected_size << 4) | (nib & 0x0F)
                            receiving_size = False
                            print(f"Expected file size: {expected_size} bytes")

                # Receiving the file extension (extension sub-command)
                elif part_sub == SUB_EXTENSION:
                    ext_code = nibble
                    file_extension = EXTENSION_MAP.get(ext_code, "bin")
                    receiving = True  # Now it can start receiving data
                    if file_extension == "msg":
                        print(f"Content type: Text message (code: 0x{ext_code:X})")
                    else:
                        print(f"Extension received: .{file_extension} (code: 0x{ext_code:X})")
                    print("\nReceiving data...")

            # END command (end of transmission)
            elif seq_cmd == CMD_END:

                # Checks if the nibble has the correct magic number to confirm the end
                if nibble != MAGIC_NIBBLE:
                    ignored_packets += 1
                    continue

                print("\nEnd (END) packet received - Finalizing reception")

                received_size = len(file_buffer)

                # Check if it's a text message or a file
                if file_extension == "msg":
                    # Text message mode: decode and display
                    decoded_message = file_buffer.decode("utf-8", errors="replace")

                    print("=" * 50)
                    print("Message received successfully!")
                    print(f"Message: {decoded_message}")
                    print(f"Bytes received:     {received_size}")
                    print(f"Bytes expected:     {expected_size}")
                    print(f"Data packets:       {data_packets}")
                    print(f"Ignored packets:    {ignored_packets}")
                else:
                    # File mode: save to disk
                    # File path to save, passed directly via CLI if provided
                    if len(sys.argv) > 1:
                        save_path = sys.argv[1]
                    else:
                        save_path = f"received.{file_extension}"

                    # wb saves in binary mode to avoid corrupting files like images or executables
                    with open(save_path, "wb") as f:
                        f.write(file_buffer)

                    print("=" * 50)
                    print("Reception completed successfully!")
                    print(f"File saved as:      {save_path}")
                    print(f"Bytes received:     {received_size}")
                    print(f"Bytes expected:     {expected_size}")
                    print(f"Data packets:       {data_packets}")
                    print(f"Ignored packets:    {ignored_packets}")

                # Simple integrity check
                if received_size == expected_size:
                    print("Integrity: OK (sizes match perfectly)")
                else:
                    print(f"Integrity: WARNING (difference of {abs(expected_size - received_size)} bytes)")
                print("=" * 50)

                break

        # If it's a DATA packet (Bit 7 == 0)
        elif ctx == CTX_DATA:

            # Only processes data packets if the session was already started by START
            if not receiving:
                ignored_packets += 1
                continue

            # Parity check to verify if the nibble arrived corrupted
            if not validate_parity(nibble, parity):
                ignored_packets += 1
                continue

            data_packets += 1

            # If it's the high nibble (bits 7 to 4)
            if part_sub == PART_HIGH:
                temp_high_nibble = nibble

            # If it's the low nibble (bits 3 to 0)
            elif part_sub == PART_LOW:
                if temp_high_nibble is not None:
                    # Joins the high and low nibbles to reassemble the original file byte
                    complete_byte = (temp_high_nibble << 4) | nibble
                    file_buffer.append(complete_byte)

                    # Clears the temporary variable for the next byte
                    temp_high_nibble = None

                    # Flips the expected sequence bit using XOR
                    expected_seq ^= 1

                    # Progress prints every 10%
                    bytes_received = len(file_buffer)
                    step_10_percent = max(1, expected_size // 10)
                    is_done = (bytes_received == expected_size)

                    if (bytes_received % step_10_percent == 0) or is_done:
                        if expected_size > 0:
                            percentage = (bytes_received / expected_size) * 100
                            print(f"{bytes_received}/{expected_size} bytes received: {percentage:.2f}% completed")
