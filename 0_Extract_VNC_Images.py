import zlib
from scapy.all import rdpcap, TCP, Raw
from PIL import Image
import io
from collections import defaultdict

# Set framebuffer size based on 'Client framebuffer update request' packet
framebuffer_width = 1280
framebuffer_height = 800

pcap_file = "file.pcapng"
packets = rdpcap(pcap_file)

streams = defaultdict(list)

# Group payloads by TCP stream (source / destination (IP(v6)) and port)
for pkt in packets:
    if TCP in pkt and Raw in pkt:
        ip = pkt.payload
        tcp = pkt[TCP]
        key = tuple(sorted([
            (ip.src, tcp.sport),
            (ip.dst, tcp.dport)
        ]))
        streams[key].append((tcp.seq, bytes(pkt[Raw].load)))

# Sort streams and reassemble
for key, pkts in streams.items():
    print(f"\nStream: {key}")
    pkts.sort()
    stream_data = b''.join(payload for _, payload in pkts)

    i = 0
    frame_count = 0
    while i + 4 <= len(stream_data):
        msg_type = stream_data[i]
        if msg_type == 0:  # FramebufferUpdate
            if i + 4 > len(stream_data):
                break
            rect_count = int.from_bytes(stream_data[i+2:i+4], 'big')
            i += 4

            # New image canvas
            canvas = Image.new("RGB", (framebuffer_width, framebuffer_height))

            for _ in range(rect_count):
                if i + 12 > len(stream_data):
                    break

                x = int.from_bytes(stream_data[i:i+2], 'big')
                y = int.from_bytes(stream_data[i+2:i+4], 'big')
                w = int.from_bytes(stream_data[i+4:i+6], 'big')
                h = int.from_bytes(stream_data[i+6:i+8], 'big')
                encoding = int.from_bytes(stream_data[i+8:i+12], 'big', signed=True)
                i += 12

                # Tight encoding
                if encoding == 7:  
                    if i >= len(stream_data):
                        break
                    control = stream_data[i]
                    i += 1
                    
                    # JPEG
                    if control & 0x80:  
                        jpeg_len = 0
                        shift = 0
                        while True:
                            if i >= len(stream_data): break
                            b = stream_data[i]
                            i += 1
                            jpeg_len |= (b & 0x7F) << shift
                            if not b & 0x80: break
                            shift += 7
                        jpeg_data = stream_data[i:i+jpeg_len]
                        i += jpeg_len
                        try:
                            img = Image.open(io.BytesIO(jpeg_data))
                            canvas.paste(img, (x, y))
                        except Exception as e:
                            print(f"Error with JPEG image data at x={x}, y={y}: {e}")
                            continue
                    
                    # Solid fill
                    elif control & 0x08:  
                        if i + 3 > len(stream_data):
                            break
                        r, g, b = stream_data[i:i+3]
                        i += 3
                        fill = Image.new("RGB", (w, h), (r, g, b))
                        canvas.paste(fill, (x, y))

                    # ZLIB (compressed)
                    elif control & 0x04:  
                        zlib_len = 0
                        shift = 0
                        while True:
                            if i >= len(stream_data): break
                            b = stream_data[i]
                            i += 1
                            zlib_len |= (b & 0x7F) << shift
                            if not b & 0x80: break
                            shift += 7
                        compressed = stream_data[i:i+zlib_len]
                        i += zlib_len
                        try:
                            decompressed = zlib.decompress(compressed)
                            img = Image.frombytes("RGB", (w, h), decompressed)
                            canvas.paste(img, (x, y))
                        except Exception as e:
                            print(f"Error with ZLIB decompression at x={x}, y={y}: {e}")
                            continue

                    else:
                        print(f"Unsupported encoding control: {control}")
                else:
                    print(f"Non-tight encoding {encoding} found; skipping.")
                    continue

            # Save image
            frame_count += 1
            canvas.save(f"./output/framebuffer_{frame_count:03d}.png")
            print(f"Saved framebuffer_{frame_count:03d}.png")

        else:
            i += 1
