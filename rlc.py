import struct
import time
from extract2 import LCIDConfig, EEA
from key import *
from rrc import *

# --- ---
class SimplePcapWriter:
    """
    Class to create a PCAP file using pure Python without Scapy.
    The Global Header and Packet Header are constructed directly using the struct module.
    """
    def __init__(self, filename, network=1, snaplen=65535):
        """
        filename: output pcap path
        network:  PCAP linktype (default 1 = Ethernet)
                  e.g., 151 = DLT_USER4 for mapping to lte-rrc.dl.dcch
        snaplen:  max captured length per packet
        """
        self.filename = filename
        self.network = network
        self.snaplen = snaplen

        self.f = open(filename, "wb")
        self._write_global_header()

    def _write_global_header(self):
        """
        Writes the PCAP Global Header (24 bytes)
        Magic Number: 0xa1b2c3d4 (Microseconds)
        Version: 2.4
        Network: self.network (default 1 = Ethernet)
        """
        magic_number = 0xa1b2c3d4
        version_major = 2
        version_minor = 4
        thiszone = 0
        sigfigs = 0

        header = struct.pack(
            '<IHHIIII',
            magic_number,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            int(self.snaplen),
            int(self.network)
        )
        self.f.write(header)
        self.f.flush()

    def write_packet(self, payload_bytes):
        """
        Writes the PCAP Packet Header + Packet Data
        """
        ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        incl_len = len(payload_bytes)
        orig_len = len(payload_bytes)

        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)

        self.f.write(pkt_header)
        self.f.write(payload_bytes)
        self.f.flush()

    def close(self):
        self.f.close()

# ****************************************** #

class LteRlcAmReassembler:
    def __init__(self, lcid_config: LCIDConfig):
        self.pcap_writer = SimplePcapWriter(lcid_config.filename)
        
        # AM Constants (10-bit SN)
        self.SN_MODULUS = 1024
        self.WINDOW_SIZE = 512
        
        # State Variables
        self.vr_r = 0  # Receive state variable (Next expected SN)
        
        # Reordering Buffer
        # Key: SN, Value: List of segments [(so, data, is_last),...]
        self.am_window = {}
        
        # SDU Assembly Buffer (Partial SDU)
        self.sdu_buffer = []

        self.config = lcid_config

    def process_rlc_pdu(self, raw_bytes):
        """
        Public Method: Entry point called from external code
        """
        try:
            header = self._parse_am_header(raw_bytes)
        except ValueError as e:
            print(f"[Parse Error] {e}")
            return
        # Control PDU (Status PDU) is skipped as it's irrelevant to data restoration
        print(header)
        if header['dc'] == 0:
            pass
        # Execute reordering and reassembly process
        self._handle_incoming_segment(header)

    def _parse_am_header(self, raw_bytes):
        """
        LTE RLC AM Header Parsing (TS 36.322)
        Handles Variable Header Length based on RF flag
        """
        if len(raw_bytes) < 2:
            raise ValueError("PDU too short")

        cursor = 0
        b0 = raw_bytes[cursor]
        b1 = raw_bytes[cursor+1]
        cursor += 2

        # --- Fixed Header Part 1 (2 Bytes) ---
        # Byte 0: D/C(1) | RF(1) | P(1) | FI(2) | E(1) | SN_MSB(2)
        # Byte 1: SN_LSB(8)
        
        dc = (b0 >> 7) & 0x01
        rf = (b0 >> 6) & 0x01  # <--- Key: Resegmentation Flag
        p  = (b0 >> 5) & 0x01
        fi = (b0 >> 3) & 0x03
        e  = (b0 >> 2) & 0x01
        sn = ((b0 & 0x03) << 8) | b1

        lsf = 0
        so = 0

        # --- Segment Header Part (RF=1 check) ---
        if rf == 1:
            if len(raw_bytes) < cursor + 2:
                raise ValueError("Segment Header truncated")
            
            b2 = raw_bytes[cursor]
            b3 = raw_bytes[cursor+1]
            cursor += 2
            
            # Byte 2: LSF(1) | SO_MSB(7)
            # Byte 3: SO_LSB(8)
            lsf = (b2 >> 7) & 0x01
            so  = ((b2 & 0x7F) << 8) | b3
        else:
            # If RF=0, it's a full PDU, so Offset is 0, and it's the Last Segment
            lsf = 1
            so = 0

        # --- Extension Part (Length Indicators) ---
        lis = []
        if e == 1:
            # LI Parsing Logic (1.5 byte unit processing)
            # Similar to before, but simplified here or 
            # the standard LI parsing logic must be used.
            # (AM's LI is 11 bits, same structure as UM)
            current_byte_idx = cursor
            current_bit_offset = 0 # 0 or 4
            
            while True:
                
                if current_byte_idx + 1 >= len(raw_bytes):
                    break # Safety break
                
                w = (raw_bytes[current_byte_idx] << 8) | raw_bytes[current_byte_idx+1]
                
                if current_bit_offset == 0:
                    val = (w >> 4) & 0xFFF # 12 bits
                    current_byte_idx += 1
                    current_bit_offset = 4
                else:
                    val = w & 0xFFF
                    current_byte_idx += 2
                    current_bit_offset = 0
                
                e_next = (val >> 11) & 0x01
                li_val = val & 0x7FF
                lis.append(li_val)
                
                if e_next == 0:
                    break
            
            cursor = current_byte_idx
            if current_bit_offset == 4:
                cursor += 1 # Padding handling

        payload = raw_bytes[cursor:]

        return {
            'sn': sn,
            'dc': dc,
            'rf': rf,
            'fi': fi,
            'lsf': lsf,
            'so': so,
            'lis': lis,
            'payload': payload
        }

    def _handle_incoming_segment(self, header):
        """
        Aligns segments based on SN and SO, and extracts the Payload
        """
        sn = header['sn']
        
        # Window Check (Simplified)
        # Actual implementation requires VR(R) update logic
        distance = (sn - self.vr_r) % self.SN_MODULUS
        
        if distance >= self.WINDOW_SIZE:
            return # Ignore packet outside the window

        if sn not in self.am_window:
            self.am_window[sn] = []

        # Store segment: (SO, Payload, HeaderInfo)
        self.am_window[sn].append(header)
        
        # Check if all segments for this SN have arrived, or if they can be processed sequentially
        # Simplification: "Attempt immediate processing after sorting by SO based on arrival order"
        # (Perfect ARQ reassembly requires hole-filling logic, but sorting and processing is efficient for PCAP generation)
        self.am_window[sn].sort(key=lambda x: x['so'])
        
        # Process available segments
        self._try_reassemble_segments(sn)

    def _try_reassemble_segments(self, sn):
        segments = self.am_window[sn]
        
        # Variable for segment continuity check
        expected_so = 0 
        
        # Segments that have been processed need to be removed from the list
        processed_count = 0
        
        for seg in segments:
            # Does it match the offset that should be processed now?
            # (Note: Actual implementation has more complex logic for handling duplicate received segments)
            if seg['so'] == expected_so:
                # Process data
                self._extract_sdus_from_payload(seg)
                
                expected_so += len(seg['payload'])
                processed_count += 1
                
                # If this is the last segment (LSF=1), this SN is complete
                # (Under the premise that the preceding parts are all filled)
                if seg['lsf'] == 1:
                    # SN processing complete, advance window (Simplification: wait for next SN)
                    if sn == self.vr_r:
                        self.vr_r = (self.vr_r + 1) % self.SN_MODULUS
            else:
                # Gap found, stop processing and wait for the next packet
                break
        
        # Remove processed segments
        self.am_window[sn] = segments[processed_count:]

    def _extract_sdus_from_payload(self, seg):
        """
        Assembles SDU fragments based on LI and FI within the segment
        """
        payload = seg['payload']
        lis = seg['lis']
        fi = seg['fi']
        
        cursor = 0
        
        # FI bit interpretation
        # FI(00): Start & End exist (Full SDU inside or multiple)
        # FI(01): Start exists, End does not (First part)
        # FI(10): Start does not, End exists (Last part)
        # FI(11): No Start, No End (Middle part)
        
        # Note: When segmented, the FI bits refer to the data attributes relative to 'that segment'
        # That is, the logic can treat it as a "Data Stream," same as UM
        
        is_first_byte_start = (fi & 0x02) == 0
        is_last_byte_end = (fi & 0x01) == 0

        # LI loop: Internal boundary handling
        for li in lis:
            chunk = payload[cursor : cursor + li]
            cursor += li
            
            if cursor == li: # First chunk
                if not is_first_byte_start:
                    # Tail part of the previous SDU
                    self.sdu_buffer.append(chunk)
                    self._flush_sdu() # Complete
                else:
                    # A complete chunk of a new SDU
                    self._write_ip_packet(chunk)
            else:
                # Middle chunks are unconditionally complete SDUs
                self._write_ip_packet(chunk)

        # Process remaining data
        remainder = payload[cursor:]
        if remainder:
            if not lis: # If no LI, follow the start property of FI
                if not is_first_byte_start:
                    self.sdu_buffer.append(remainder)
                else:
                    # Discard residue in SDU buffer (Packet loss scenario)
                    if self.sdu_buffer:
                        self.sdu_buffer = []
                    self.sdu_buffer.append(remainder)
            else: # If LI existed, the remainder is unconditionally the start of a new SDU
                if self.sdu_buffer:
                    self.sdu_buffer = []# Safety check
                self.sdu_buffer.append(remainder)
            
            # Is this the end?
            if is_last_byte_end:
                self._flush_sdu()

    def _flush_sdu(self):
        """Combines buffer contents and writes to PCAP"""
        if not self.sdu_buffer:
            return
        
        full_data = b''.join(self.sdu_buffer)
        self._write_ip_packet(full_data)
        self.sdu_buffer = []

    def _write_ip_packet(self, data):
        """
        Checks if it's an IP packet, then wraps it in an Ethernet frame and saves
        """
        if len(data) < 22:
            return # Minimum IP header length

        print("SDU!", data.hex())
        sdu_length = 2
        
        #for i in range(1, 4):
        #    if (data[i] >> 4) == 4 or (data[i] >> 4) == 6:
        #        sdu_length = i
        #        break

        pdu = data[:sdu_length]
        data = data[sdu_length:]

        x = int.from_bytes(pdu, byteorder="big", signed=False)
        cnt = x & 0xFFF # 12-bit assumed

        if self.config.prev_cnt - cnt > 2048:
            self.config.hfn += 1

        self.config.prev_cnt = cnt

        print(f"cnt: {cnt}")
        print(f"bearer: {self.config.bearer}")
        
        # decrypt
        if self.config.eea == EEA.EEA0:
            pass
        elif self.config.eea == EEA.EEA2:
            if self.config.bearer != -1:
                data = liblte_security_encryption_eea2(
                    self.config.key[16:],
                    4096 * self.config.hfn + cnt,
                    self.config.bearer-1,
                    1,
                    data,
                    len(data) * 8
                )
            else:
                bearer_candidates = []

                for candidate in range(1, 32):
                    data2 = liblte_security_encryption_eea2(
                        self.config.key[16:],
                        cnt,
                        candidate-1,
                        1,
                        data,
                        len(data) * 8
                    )

                    if (data2[0] >> 4) == 0x6 or (data2[0] == 0x45 and data2[1] == 0):
                        print("yayyy")
                        bearer_candidates.append(candidate)
                        print(f"This may contain deciphered message with bearer: {candidate}")
                        print(f"May be deciphered: {data2.hex()}")

        print("Deciphered SDU!", data.hex())

        # IP Version Check (First nibble)
        version = (data[0] >> 4)
        eth_type = b'\x08\x00' if version == 4 else b'\x86\xdd' if version == 6 else b'\x00\x00'

        print("ETH", eth_type)

        if eth_type:
            # Dummy MAC Address
            eth_header = b'\x00\x02\x00\x00\x00\x02' + b'\x00\x02\x00\x00\x00\x01' + eth_type
            self.pcap_writer.write_packet(eth_header + data)
            #self.pcap_writer.f.close()
            #assert(0)

    def close(self):
        self.pcap_writer.close()

# ****************************************** #

class LteRlcUm5BitReassembler:
    """
    LTE RLC UM Reassembler for 5-bit Sequence Number (VoLTE)
    """
    def __init__(self, lcid_config: LCIDConfig):
        self.pcap_writer = SimplePcapWriter(lcid_config.filename)
        
        # UM 7-bit constants
        self.SN_MODULUS = 32       # 2^5
        self.WINDOW_SIZE = 16      # 2^5 / 2
        
        # State Variables
        self.vr_ur = 0  # Reordering state variable (Expected SN)
        self.vr_uh = 0  # Highest received state variable
        
        # Reordering Buffer: { sn: pdu_context }
        self.reorder_buffer = {}
        
        # SDU Assembly Buffer (fragmented chunks)
        # VoLTE often involves small packets, so simple byte concatenation is used instead of a list
        self.assembly_buffer = b"" 
        
        self.config = lcid_config

    def process_rlc_pdu(self, raw_bytes):
        """
        Main function to process the incoming MAC SDU (RLC PDU)
        """
        try:
            header = self._parse_header(raw_bytes)
        except ValueError as e:
            print(f"[Parse Error] {e}")
            return

        # Execute window management and reordering logic
        self._handle_incoming_pdu(header)

    def _parse_header(self, raw_bytes):
        """
        RLC UM 5-bit SN Header Parsing (Bit-level processing)
        """
        if len(raw_bytes) < 1:
            raise ValueError("PDU empty")

        cursor = 0
        
        # --- Fixed Header (1 Byte) ---
        # Format: FI(2) | E(1) | SN(5)
        byte0 = raw_bytes[cursor]
        cursor += 1
        
        fi = (byte0 >> 6) & 0x03
        e  = (byte0 >> 5) & 0x01
        sn = byte0 & 0x1F

        lis = []
        
        # --- Extension Part (Variable Length) ---
        # If E=1, LI (11 bits) + E (1 bit) repeats
        if e == 1:
            # Track offset for bit-level access
            # current_byte_idx is 1 (start of the second byte)
            # bit_pos is the current bit position being processed (0 ~ 7)
            # However, integer arithmetic is used for 1.5 byte (12 bit) processing
            
            current_byte_idx = cursor
            current_nibble = 0 # 0: Upper 12 bits starting at byte boundary
                               # 1: Lower 12 bits starting middle of byte
            
            while True:
                if current_byte_idx + 1 >= len(raw_bytes):
                    raise ValueError("Header parsing overflow")

                # Read 2 bytes to create a 16-bit window
                w = (raw_bytes[current_byte_idx] << 8) | raw_bytes[current_byte_idx+1]
                
                val = 0
                if current_nibble == 0:
                    # Extract A entire + B upper 4 bits (12 bits)
                    val = (w >> 4) & 0xFFF
                    # Next state: byte index +1, nibble offset 1
                    current_byte_idx += 1
                    current_nibble = 1
                else:
                    # Extract A lower 4 bits + B entire (12 bits)
                    val = w & 0xFFF
                    # Next state: byte index +2 (A, B both consumed), nibble offset 0
                    current_byte_idx += 2
                    current_nibble = 0
                
                next_e = (val >> 11) & 0x01
                li_val = val & 0x7FF
                lis.append(li_val)
                
                if next_e == 0:
                    break
            
            # --- Padding Logic (Crucial for 5-bit SN) ---
            # If the number of LIs is odd, 4 bits of padding exist to align to byte boundary
            # If current_nibble is 1, 0.5 bytes (4 bits) remain -> consumed by padding
            if current_nibble == 1:
                current_byte_idx += 1 # Skip remaining 4 bits of padding
                
            cursor = current_byte_idx

        payload = raw_bytes[cursor:]
        
        return {
            'sn': sn,
            'fi': fi,
            'lis': lis,
            'payload': payload
        }

    def _handle_incoming_pdu(self, pdu):
        sn = pdu['sn']
        
        # --- Window Check (Modulo 32) ---
        # distance = (SN - VR_UH) mod 32
        # VR_UH: Next expected highest SN
        
        # UM Window Logic (Simplified based on RFC/3GPP):
        # If SN is inside the window (past/duplicate), ignore or buffer.
        # If SN is outside the window (future), advance the window.
        
        distance = (sn - self.vr_uh) % self.SN_MODULUS
        
        # Valid window: (VR_UH - Window_Size) <= SN < VR_UH
        # In implementation, if distance is smaller than Window_Size, it's an "old packet" or "reordering target"
        # If distance is large (i.e., acts like a negative number), it's a "new packet"
        
        # Here, processing is simplified based on "VR_UR (Expected SN)"
        diff = (sn - self.vr_ur) % self.SN_MODULUS
        
        if diff < self.WINDOW_SIZE:
            # Normal range (came in order, slightly late, or a future packet)
            self.reorder_buffer[sn] = pdu
        else:
            # Far outside the window (very old packet or needs reset)
            # Here, the window is forcefully moved to SN (Resync)
            # Actual implementation requires clearing the buffer, etc.
            self.vr_ur = sn
            self.reorder_buffer = {sn: pdu}

        # --- Reassembly Loop ---
        # Check and process consecutive packets starting from VR_UR
        while self.vr_ur in self.reorder_buffer:
            curr_pdu = self.reorder_buffer.pop(self.vr_ur)
            self._reassemble_pdu(curr_pdu)
            self.vr_ur = (self.vr_ur + 1) % self.SN_MODULUS
            
            # Update VR_UH (Advance window upper boundary)
            # Since VR_UR has moved, VR_UH must be at least greater than VR_UR
            # (Accurate VR_UH management is complex, so here it follows VR_UR)
            pass

    def _reassemble_pdu(self, pdu):
        """
        Assembles SDU using FI and LI and saves to PCAP
        """
        fi = pdu['fi']
        lis = pdu['lis']
        payload = pdu['payload']
        cursor = 0
        
        # FI Interpretation:
        # 00: Complete SDU inside
        # 01: First byte is SDU start
        # 10: Last byte is SDU end
        # 11: Middle segment
        
        is_first_byte_start = (fi & 0x02) == 0  # Bit 1 is 0?
        is_last_byte_end    = (fi & 0x01) == 0  # Bit 0 is 0?

        # 1. Handle LIs (Internal Boundaries)
        for li in lis:
            # Extract chunk of LI length
            if cursor + li > len(payload):
                print(f"Error: LI({li}) > Payload left")
                return
            
            chunk = payload[cursor : cursor + li]
            cursor += li
            
            # Process first chunk
            if cursor == li:
                if not is_first_byte_start:
                    # Remainder of the previous SDU
                    self.assembly_buffer += chunk
                    self._flush_sdu()
                else:
                    # Start and end of a new SDU (ended by LI)
                    self._write_ip_packet(chunk)
            else:
                # Intermediate LIs: unconditionally complete SDUs
                self._write_ip_packet(chunk)

        # 2. Handle Remainder (Last part of payload)
        remainder = payload[cursor:]
        if remainder:
            # If no LI, follow the start property of FI
            # If LI existed, the SDU ended at the previous LI, so the remainder is the 'start of a new SDU'
            is_new_start = is_first_byte_start if not lis else True
            
            if not is_new_start:
                self.assembly_buffer += remainder
            else:
                # Discard if there was an incomplete one previously (Assumed packet loss)
                if self.assembly_buffer:
                    # print("Warning: Incomplete SDU discarded")
                    self.assembly_buffer = b""
                self.assembly_buffer += remainder
            
            # Check end property
            if is_last_byte_end:
                self._flush_sdu()

    def _flush_sdu(self):
        if self.assembly_buffer:
            self._write_ip_packet(self.assembly_buffer)
            self.assembly_buffer = b""

    def _write_ip_packet(self, data):
        """
        Checks if it's an IP packet, then wraps it in an Ethernet frame and saves
        """
        if len(data) < 22:
            return # Minimum IP header length

        print("SDU!", data.hex())
        sdu_length = 1
        
        #for i in range(1, 4):
        #    if (data[i] >> 4) == 4 or (data[i] >> 4) == 6:
        #        sdu_length = i
        #        break

        pdu = data[:sdu_length]
        data = data[sdu_length:]

        cnt = int.from_bytes(pdu) & 0x7f # 7-bit assumed

        if self.config.prev_cnt - cnt > 64:
            self.config.hfn += 1
        
        self.config.prev_cnt = cnt

        print(f"cnt: {128 * self.config.hfn + cnt} ({cnt})")
        print(f"bearer: {self.config.bearer}")
        
        # decrypt
        if self.config.eea == EEA.EEA0:
            pass
        elif self.config.eea == EEA.EEA2:
            if self.config.bearer != -1:
                data = liblte_security_encryption_eea2(
                    self.config.key[16:],
                    128 * self.config.hfn + cnt,
                    self.config.bearer-1,
                    1,
                    data,
                    len(data) * 8
                )
            else:
                bearer_candidates = []

                for candidate in range(1, 32):
                    data2 = liblte_security_encryption_eea2(
                        self.config.key[16:],
                        cnt,
                        candidate-1,
                        1,
                        data,
                        len(data) * 8
                    )

                    if (data2[0] >> 4) == 0x6 or (data2[0] == 0x45 and data2[1] == 0):
                        print("yayyy")
                        bearer_candidates.append(candidate)
                        print(f"This may contain deciphered message with bearer: {candidate}")
                        print(f"May be deciphered: {data2.hex()}")

        print("Deciphered SDU!", data.hex())

        # IP Version Check (First nibble)
        version = (data[0] >> 4)
        eth_type = b'\x08\x00' if version == 4 else b'\x86\xdd' if version == 6 else b'\x00\x00'

        print("ETH", eth_type)

        if eth_type:
            # Dummy MAC Address
            eth_header = b'\x00\x02\x00\x00\x00\x02' + b'\x00\x02\x00\x00\x00\x01' + eth_type
            self.pcap_writer.write_packet(eth_header + data)
            #self.pcap_writer.f.close()
            #assert(0)

    def close(self):
        self.pcap_writer.close()

# ****************************************** #

class LteRlcNasReassembler:
    def __init__(self, lcid_config: LCIDConfig):
        self.pcap_writer = SimplePcapWriter(lcid_config.filename, network=151)
        
        # AM Constants (10-bit SN)
        self.SN_MODULUS = 1024
        self.WINDOW_SIZE = 512
        
        # State Variables
        self.vr_r = 0  # Receive state variable (Next expected SN)
        
        # Reordering Buffer
        # Key: SN, Value: List of segments [(so, data, is_last),...]
        self.am_window = {}
        
        # SDU Assembly Buffer (Partial SDU)
        self.sdu_buffer = []

        self.config = lcid_config

    def process_rlc_pdu(self, raw_bytes):
        """
        Public Method: Entry point called from external code
        """
        try:
            header = self._parse_am_header(raw_bytes)
        except ValueError as e:
            print(f"[Parse Error] {e}")
            return
        # Control PDU (Status PDU) is skipped as it's irrelevant to data restoration
        print(header)
        if header['dc'] == 0:
            pass
        # Execute reordering and reassembly process
        self._handle_incoming_segment(header)

    def _parse_am_header(self, raw_bytes):
        """
        LTE RLC AM Header Parsing (TS 36.322)
        Handles Variable Header Length based on RF flag
        """
        if len(raw_bytes) < 2:
            raise ValueError("PDU too short")

        cursor = 0
        b0 = raw_bytes[cursor]
        b1 = raw_bytes[cursor+1]
        cursor += 2

        # --- Fixed Header Part 1 (2 Bytes) ---
        # Byte 0: D/C(1) | RF(1) | P(1) | FI(2) | E(1) | SN_MSB(2)
        # Byte 1: SN_LSB(8)
        
        dc = (b0 >> 7) & 0x01
        rf = (b0 >> 6) & 0x01  # <--- Key: Resegmentation Flag
        p  = (b0 >> 5) & 0x01
        fi = (b0 >> 3) & 0x03
        e  = (b0 >> 2) & 0x01
        sn = ((b0 & 0x03) << 8) | b1

        lsf = 0
        so = 0

        # --- Segment Header Part (RF=1 check) ---
        if rf == 1:
            if len(raw_bytes) < cursor + 2:
                raise ValueError("Segment Header truncated")
            
            b2 = raw_bytes[cursor]
            b3 = raw_bytes[cursor+1]
            cursor += 2
            
            # Byte 2: LSF(1) | SO_MSB(7)
            # Byte 3: SO_LSB(8)
            lsf = (b2 >> 7) & 0x01
            so  = ((b2 & 0x7F) << 8) | b3
        else:
            # If RF=0, it's a full PDU, so Offset is 0, and it's the Last Segment
            lsf = 1
            so = 0

        # --- Extension Part (Length Indicators) ---
        lis = []
        if e == 1:
            # LI Parsing Logic (1.5 byte unit processing)
            # Similar to before, but simplified here or 
            # the standard LI parsing logic must be used.
            # (AM's LI is 11 bits, same structure as UM)
            current_byte_idx = cursor
            current_bit_offset = 0 # 0 or 4
            
            while True:
                
                if current_byte_idx + 1 >= len(raw_bytes):
                    break # Safety break
                
                w = (raw_bytes[current_byte_idx] << 8) | raw_bytes[current_byte_idx+1]
                
                if current_bit_offset == 0:
                    val = (w >> 4) & 0xFFF # 12 bits
                    current_byte_idx += 1
                    current_bit_offset = 4
                else:
                    val = w & 0xFFF
                    current_byte_idx += 2
                    current_bit_offset = 0
                
                e_next = (val >> 11) & 0x01
                li_val = val & 0x7FF
                lis.append(li_val)
                
                if e_next == 0:
                    break
            
            cursor = current_byte_idx
            if current_bit_offset == 4:
                cursor += 1 # Padding handling

        payload = raw_bytes[cursor:]

        return {
            'sn': sn,
            'dc': dc,
            'rf': rf,
            'fi': fi,
            'lsf': lsf,
            'so': so,
            'lis': lis,
            'payload': payload
        }

    def _handle_incoming_segment(self, header):
        """
        Aligns segments based on SN and SO, and extracts the Payload
        """
        sn = header['sn']
        
        # Window Check (Simplified)
        # Actual implementation requires VR(R) update logic
        distance = (sn - self.vr_r) % self.SN_MODULUS
        
        if distance >= self.WINDOW_SIZE:
            return # Ignore packet outside the window

        if sn not in self.am_window:
            self.am_window[sn] = []

        # Store segment: (SO, Payload, HeaderInfo)
        self.am_window[sn].append(header)
        
        # Check if all segments for this SN have arrived, or if they can be processed sequentially
        # Simplification: "Attempt immediate processing after sorting by SO based on arrival order"
        # (Perfect ARQ reassembly requires hole-filling logic, but sorting and processing is efficient for PCAP generation)
        self.am_window[sn].sort(key=lambda x: x['so'])
        
        # Process available segments
        self._try_reassemble_segments(sn)

    def _try_reassemble_segments(self, sn):
        segments = self.am_window[sn]
        
        # Variable for segment continuity check
        expected_so = 0 
        
        # Segments that have been processed need to be removed from the list
        processed_count = 0
        
        for seg in segments:
            # Does it match the offset that should be processed now?
            # (Note: Actual implementation has more complex logic for handling duplicate received segments)
            if seg['so'] == expected_so:
                # Process data
                self._extract_sdus_from_payload(seg)
                
                expected_so += len(seg['payload'])
                processed_count += 1
                
                # If this is the last segment (LSF=1), this SN is complete
                # (Under the premise that the preceding parts are all filled)
                if seg['lsf'] == 1:
                    # SN processing complete, advance window (Simplification: wait for next SN)
                    if sn == self.vr_r:
                        self.vr_r = (self.vr_r + 1) % self.SN_MODULUS
            else:
                # Gap found, stop processing and wait for the next packet
                break
        
        # Remove processed segments
        self.am_window[sn] = segments[processed_count:]

    def _extract_sdus_from_payload(self, seg):
        """
        Assembles SDU fragments based on LI and FI within the segment
        """
        payload = seg['payload']
        lis = seg['lis']
        fi = seg['fi']
        
        cursor = 0
        
        # FI bit interpretation
        # FI(00): Start & End exist (Full SDU inside or multiple)
        # FI(01): Start exists, End does not (First part)
        # FI(10): Start does not, End exists (Last part)
        # FI(11): No Start, No End (Middle part)
        
        # Note: When segmented, the FI bits refer to the data attributes relative to 'that segment'
        # That is, the logic can treat it as a "Data Stream," same as UM
        
        is_first_byte_start = (fi & 0x02) == 0
        is_last_byte_end = (fi & 0x01) == 0

        # LI loop: Internal boundary handling
        for li in lis:
            chunk = payload[cursor : cursor + li]
            cursor += li
            
            if cursor == li: # First chunk
                if not is_first_byte_start:
                    # Tail part of the previous SDU
                    self.sdu_buffer.append(chunk)
                    self._flush_sdu() # Complete
                else:
                    # A complete chunk of a new SDU
                    self._write_ip_packet(chunk)
            else:
                # Middle chunks are unconditionally complete SDUs
                self._write_ip_packet(chunk)

        # Process remaining data
        remainder = payload[cursor:]
        if remainder:
            if not lis: # If no LI, follow the start property of FI
                if not is_first_byte_start:
                    self.sdu_buffer.append(remainder)
                else:
                    # Discard residue in SDU buffer (Packet loss scenario)
                    if self.sdu_buffer:
                        self.sdu_buffer = []
                    self.sdu_buffer.append(remainder)
            else: # If LI existed, the remainder is unconditionally the start of a new SDU
                if self.sdu_buffer:
                    self.sdu_buffer = []# Safety check
                self.sdu_buffer.append(remainder)
            
            # Is this the end?
            if is_last_byte_end:
                self._flush_sdu()

    def _flush_sdu(self):
        """Combines buffer contents and writes to PCAP"""
        if not self.sdu_buffer:
            return
        
        full_data = b''.join(self.sdu_buffer)
        self._write_ip_packet(full_data)
        self.sdu_buffer = []

    def _write_ip_packet(self, data):
        """
        Checks if it's an IP packet, then wraps it in an Ethernet frame and saves
        """

        print("SDU!", data.hex())
        sdu_length = 1
        
        pdu = data[:sdu_length]
        data = data[sdu_length:-4]
        mac = data[-4:]

        cnt = int.from_bytes(pdu) & 0x7f # 7-bit assumed

        if self.config.prev_cnt - cnt > 64:
            self.config.hfn += 1

        self.config.prev_cnt = cnt

        print(f"cnt: {cnt}")
        print(f"bearer: {self.config.bearer}")
        
        # decrypt
        if self.config.eea == EEA.EEA0:
            pass
        elif self.config.eea == EEA.EEA2:
            data = liblte_security_encryption_eea2(
                self.config.key[16:],
                128 * self.config.hfn + cnt,
                self.config.bearer - 1,
                1,
                data,
                len(data) * 8
            )

        print("Deciphered SDU!", data.hex())
        data = process_nas_by_rrc(data, self.config.aux['k_nas_enc'], 1)
        print("Processed SDU!", data.hex())

        drbs = print_added_drb_info(data)
        for drb in drbs:
            self.config.aux['update_lcid'](drb)

        self.pcap_writer.write_packet(data)


    def close(self):
        self.pcap_writer.close()

