import csv
from scapy.all import rdpcap, TCP, Raw, IP, IPv6
from collections import defaultdict

input_pcap = "./file.pcapng"

# Keysyms map
keysym_map = {
    # Printable ASCII characters
    **{i: chr(i) for i in range(32, 127)},  # Printable ASCII characters
    0xFF08: "Backspace", 0xFF09: "Tab", 0xFF0D: "Enter", 0xFF1B: "Escape", 0xFFFF: "Delete",
    0xFFBE: "F1", 0xFFBF: "F2", 0xFFC0: "F3", 0xFFC1: "F4", 0xFFC2: "F5", 0xFFC3: "F6",
    0xFFC4: "F7", 0xFFC5: "F8", 0xFFC6: "F9", 0xFFC7: "F10", 0xFFC8: "F11", 0xFFC9: "F12",
    0xFF50: "Home", 0xFF57: "End", 0xFF55: "Page Up", 0xFF56: "Page Down",
    0xFF51: "Left", 0xFF52: "Up", 0xFF53: "Right", 0xFF54: "Down",
    0xFFE1: "Shift_L", 0xFFE2: "Shift_R", 0xFFE3: "Control_L", 0xFFE4: "Control_R",
}

def parse_vnc_keys_to_list(pcap_file):
    packets = rdpcap(pcap_file)
    output = []
    keystroke_log = []

    shift_pressed = False
    ctrl_pressed = False
    processed_seq_nums = set()

    streams = defaultdict(list)

    for pkt in packets:
        if TCP in pkt and Raw in pkt and (IP in pkt or IPv6 in pkt):
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            tcp = pkt[TCP]
            payload = bytes(pkt[Raw].load)

            if tcp.dport == 5900:
                stream_key = (ip_layer.src, tcp.sport, ip_layer.dst, tcp.dport)
            elif tcp.sport == 5900:
                stream_key = (ip_layer.dst, tcp.dport, ip_layer.src, tcp.sport)
            else:
                continue

            seq = tcp.seq
            if (stream_key, seq) not in processed_seq_nums:
                streams[stream_key].append((seq, payload))
                processed_seq_nums.add((stream_key, seq))

    for stream_key, chunks in streams.items():
        chunks.sort(key=lambda x: x[0])
        buffer = b''.join(payload for _, payload in chunks)

        i = 0
        seen_keys = set()
        # Tracks keys that are currently pressed down
        active_keys = set()

        while i <= len(buffer) - 8:
            # Client key events
            if buffer[i] == 4:  
                down_flag = buffer[i + 1]
                key_code = int.from_bytes(buffer[i + 4:i + 8], "big")
                key_char = keysym_map.get(key_code, None)

                is_press = down_flag == 1
                is_release = down_flag == 0

                if key_char in ["Shift_L", "Shift_R"]:
                    shift_pressed = bool(down_flag)
                    i += 8
                    continue
                if key_char in ["Control_L", "Control_R"]:
                    ctrl_pressed = bool(down_flag)
                    i += 8
                    continue

                interpreted = ""

                # Recover missing keypress (synthetic) if release is seen first
                if is_release and key_code not in active_keys:
                    interpreted += "*SYNTHETIC* "
                    is_press = True
                    is_release = False

                if is_press:
                    active_keys.add(key_code)
                    seen_keys.add(key_code)

                    if key_char == "Backspace":
                        if output:
                            output.pop()
                        interpreted += "<Backspace>"
                    elif key_char == "Enter":
                        output.append("\n")
                        interpreted += "<Enter>"
                    elif key_char == " " or key_code == 0x20:
                        output.append(" ")
                        interpreted += "<Space>"
                    elif key_char and len(key_char) == 1:
                        if ctrl_pressed:
                            interpreted += f"[Ctrl+{key_char.upper()}]"
                            output.append(interpreted)
                        else:
                            char = key_char.upper() if shift_pressed else key_char
                            output.append(char)
                            interpreted += char
                    elif key_char:
                        interpreted += f"<{key_char}>"

                    if interpreted:
                        keystroke_log.append({
                            "key_code": hex(key_code),
                            "key_name": key_char,
                            "shift": shift_pressed,
                            "ctrl": ctrl_pressed,
                            "output": interpreted,
                        })

                elif is_release:
                    # Key is released
                    active_keys.discard(key_code)  

                i += 8
            else:
                i += 1

    return "".join(output), keystroke_log


def save_log_to_csv(log, filename="./output/keystroke_log.csv"):
    fieldnames = ["key_code", "key_name", "shift", "ctrl", "output"]
    with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in log:
            writer.writerow(entry)

if __name__ == "__main__":
    final_text, logs = parse_vnc_keys_to_list(input_pcap)
    print("Captured Text:\n", final_text)
    save_log_to_csv(logs)
    print("Keystroke log saved to ./output/keystroke_log.csv")
