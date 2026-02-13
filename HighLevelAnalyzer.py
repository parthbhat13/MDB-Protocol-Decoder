# MDB Protocol Decoder v10 - Full MDB Protocol Decoder
# Supported Devices: Cashless (0x10-0x17), Coin Changer (0x08-0x0F), Bill Validator (0x30-0x37)
# Author: Taymur
# Feature: Channel-based (VMC / Peripheral) decoding
# Peripheral channel: mode=0 → data, mode=1 → ACK/NAK/Checksum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting


class Hla(HighLevelAnalyzer):
    """
    MDB (Multi-Drop Bus) Protocol Decoder - v11

    Two-channel support: VMC channel and Peripheral channel are analyzed separately.

    VMC channel:   mode=1 → command address, mode=0 → data/checksum
    Peripheral:    mode=0 → response data, mode=1 → ACK(0x00)/NAK(0xFF)/Checksum
    """

    # ─── User Settings ─────────────────────────────────────────────────

    KanalTipi = ChoicesSetting(
        label='Channel Type',
        choices=('VMC (Command Sender)', 'Cashless (Payment Device)', 'Coin Changer', 'Bill Validator')
    )

    # ─── MDB Command Tables ────────────────────────────────────────────

    COMMAND_NAMES = {
        0x08: "COIN_RESET", 0x09: "COIN_SETUP", 0x0A: "COIN_TUBE_STATUS",
        0x0B: "COIN_POLL", 0x0C: "COIN_TYPE", 0x0D: "COIN_DISPENSE", 0x0F: "COIN_EXPANSION",
        0x10: "RESET", 0x11: "SETUP", 0x12: "POLL", 0x13: "VEND",
        0x14: "READER", 0x15: "REVALUE", 0x17: "EXPANSION",
        0x30: "BILL_RESET", 0x31: "BILL_SETUP", 0x32: "BILL_SECURITY",
        0x33: "BILL_POLL", 0x34: "BILL_TYPE", 0x35: "BILL_ESCROW",
        0x36: "BILL_STACKER", 0x37: "BILL_EXPANSION",
    }

    DEVICE_NAMES = {
        0x01: "Coin", 0x02: "Cashless", 0x03: "Gateway",
        0x04: "Display", 0x05: "Energy", 0x06: "Bill",
        0x08: "Cashless#2", 0x0B: "AgeVerify",
    }

    VEND_SUB = {
        0x00: "VEND_REQUEST", 0x01: "VEND_CANCEL", 0x02: "VEND_SUCCESS",
        0x03: "VEND_FAILURE", 0x04: "SESSION_COMPLETE", 0x05: "CASH_SALE",
    }
    SETUP_SUB = {0x00: "CONFIG_DATA", 0x01: "MAX_MIN_PRICES"}
    READER_SUB = {0x00: "DISABLE", 0x01: "ENABLE", 0x02: "CANCEL"}
    EXPANSION_SUB = {0x00: "REQUEST_ID", 0x04: "OPT_FEATURE"}

    POLL_RESPONSE = {
        0x00: "JUST_RESET", 0x01: "READER_CONFIG", 0x02: "DISPLAY_REQ",
        0x03: "BEGIN_SESSION", 0x04: "SESSION_CANCEL", 0x05: "VEND_APPROVED",
        0x06: "VEND_DENIED", 0x07: "END_SESSION", 0x08: "CANCELLED",
        0x09: "PERIPHERAL_ID", 0x0A: "MALFUNCTION", 0x0B: "CMD_OUT_OF_SEQ",
    }

    # VMC single-checksum commands (only 1 data byte = checksum)
    VMC_SINGLE_CHK = {0x08, 0x09, 0x0A, 0x0B, 0x10, 0x12, 0x30, 0x31, 0x33, 0x36}

    # ─── Saleae Frame Types ────────────────────────────────────────────

    result_types = {
        'vmc_cmd': {'format': 'VMC→{data.target}: {data.command}'},
        'vmc_subcmd': {'format': 'VMC→{data.target}: {data.command} → {data.sub}'},
        'vmc_data': {'format': '  {data.description}'},
        'vmc_poll': {'format': 'VMC→{data.target}: POLL'},
        'vmc_chk': {'format': 'CHK: 0x{data.hex_val}'},
        'per_ack': {'format': '→ ACK'},
        'per_nak': {'format': '✗ NAK'},
        'per_chk': {'format': 'CHK: 0x{data.hex_val}'},
        'per_just_reset': {'format': '{data.device}: JUST RESET'},
        'per_begin_session': {'format': '{data.device}: BEGIN SESSION Balance={data.balance}'},
        'per_vend_approved': {'format': '{data.device}: VEND APPROVED Amount={data.amount}'},
        'per_vend_denied': {'format': '{data.device}: VEND DENIED'},
        'per_end_session': {'format': '{data.device}: END SESSION'},
        'per_session_cancel': {'format': '{data.device}: SESSION CANCEL'},
        'per_cancelled': {'format': '{data.device}: CANCELLED'},
        'per_reader_config': {'format': '{data.device}: CONFIG L{data.level} Country={data.country} Scale={data.scale} Decimal={data.decimal}'},
        'per_display_req': {'format': '{data.device}: DISPLAY {data.duration}s'},
        'per_peripheral_id': {'format': '{data.device}: {data.manufacturer} SN:{data.serial} Model:{data.model}'},
        'per_malfunction': {'format': '{data.device}: FAULT {data.error}'},
        'per_cmd_out_seq': {'format': '{data.device}: CMD OUT OF SEQ'},
        'per_data': {'format': '  {data.description}'},
        'coin_deposited': {'format': 'Coin: DEPOSIT Type={data.type} Route={data.route}'},
        'coin_status': {'format': 'Coin: {data.status}'},
        'bill_event': {'format': 'Bill: {data.event} Type={data.type}'},
        'bill_status': {'format': 'Bill: {data.status}'},
        'mdb_data': {'format': '{data.hex_val}'},
    }

    # ─── Initialization ────────────────────────────────────────────────

    def __init__(self):
        self.PrevCommand = 0x00
        self.DataBuffer = []        # VMC data bytes
        self.ResponseBuffer = []    # Peripheral response bytes
        self.ByteCount = 0
        self.CommandDone = True     # True = command complete, ACK detection active
        self.ExpectedVMCLength = 0  # Expected data byte count (including checksum)

        # Price calculation: learned from READER_CONFIG response
        self.ScaleFactor = 1        # Scale factor from config (multiplier)
        self.DecimalPlaces = 0      # Decimal places from config

        self.IsVMC = 'VMC' in self.KanalTipi
        self.DeviceName = "VMC"
        if 'Cashless' in self.KanalTipi:
            self.DeviceName = "Cashless"
        elif 'Coin' in self.KanalTipi:
            self.DeviceName = "Coin"
        elif 'Bill' in self.KanalTipi:
            self.DeviceName = "Bill"

    def _get_device(self, cmd_code):
        """Get device name from command code."""
        return self.DEVICE_NAMES.get(cmd_code >> 3, f"0x{cmd_code:02X}")

    def _chr_display(self, v):
        """Format a byte as printable character or hex."""
        if 32 <= v <= 126:
            return f"'{chr(v)}' (0x{v:02X})"
        return f"0x{v:02X}"

    def _format_price(self, raw_value):
        """Format raw MDB price value using scale factor and decimal places."""
        actual = raw_value * self.ScaleFactor
        if self.DecimalPlaces > 0:
            divisor = 10 ** self.DecimalPlaces
            return f"{actual / divisor:.{self.DecimalPlaces}f}"
        return str(actual)

    # ─── Main Decode ───────────────────────────────────────────────────

    def decode(self, frame: AnalyzerFrame):
        if frame.type != 'data':
            return None
        raw_bytes = frame.data['data']
        if len(raw_bytes) < 2:
            return AnalyzerFrame('mdb_data', frame.start_time, frame.end_time,
                                 {'hex_val': f"0x{raw_bytes[0]:02X}"})

        ctrl_byte = raw_bytes[0]
        data_byte = raw_bytes[1]
        mode_bit = 1 if (ctrl_byte & 0x01) else 0

        if self.IsVMC:
            return self._vmc_decode(data_byte, mode_bit, frame)
        else:
            return self._peripheral_decode(data_byte, mode_bit, frame)

    # ═══════════════════════════════════════════════════════════════════
    #                         VMC CHANNEL
    # ═══════════════════════════════════════════════════════════════════

    # VMC command → subcmd → total data byte count (checksum INCLUDED)
    VMC_CMD_LENGTHS = {
        # VEND (0x13)
        (0x13, 0x00): 6,  # VEND_REQUEST: subcmd + priceH + priceL + itemH + itemL + CHK
        (0x13, 0x01): 2,  # VEND_CANCEL
        (0x13, 0x02): 4,  # VEND_SUCCESS: subcmd + itemH + itemL + CHK
        (0x13, 0x03): 2,  # VEND_FAILURE
        (0x13, 0x04): 2,  # SESSION_COMPLETE
        (0x13, 0x05): 6,  # CASH_SALE
        # SETUP (0x11)
        (0x11, 0x00): 5,  # CONFIG_DATA: subcmd + level + cols + rows + CHK
        (0x11, 0x01): 6,  # MAX_MIN_PRICES: subcmd + maxH + maxL + minH + minL + CHK
        # READER (0x14)
        (0x14, 0x00): 2,  # DISABLE
        (0x14, 0x01): 2,  # ENABLE
        (0x14, 0x02): 2,  # CANCEL
        # EXPANSION (0x17)
        (0x17, 0x00): 31, # REQUEST_ID: subcmd + mfg(3) + ser(12) + mod(12) + sw(2) + CHK
        (0x17, 0x04): 6,  # OPT_FEATURE: subcmd + 4 bytes + CHK
        # REVALUE (0x15)
        (0x15, 0x00): 4,  # LIMIT_REQUEST: subcmd + amtH + amtL + CHK
        (0x15, 0x01): 2,  # LIMIT_DENIED
    }

    # Commands with fixed length (no subcmd)
    VMC_FIXED_LENGTHS = {
        0x0C: 5,   # COIN_TYPE
        0x34: 5,   # BILL_TYPE
        0x35: 2,   # BILL_ESCROW
        0x32: 3,   # BILL_SECURITY
    }

    def _vmc_decode(self, data, mode_bit, frame):
        """VMC TX channel: mode=1 → address/command, mode=0 → data/checksum/ACK."""

        # Command byte (mode=1) → start new command
        if mode_bit:
            self.PrevCommand = data
            self.DataBuffer = []
            self.ByteCount = 0

            # Single-checksum commands → 1 data byte (checksum only)
            if data in self.VMC_SINGLE_CHK:
                self.CommandDone = False
                self.ExpectedVMCLength = 1
            # Fixed-length commands (no subcmd)
            elif data in self.VMC_FIXED_LENGTHS:
                self.CommandDone = False
                self.ExpectedVMCLength = self.VMC_FIXED_LENGTHS[data]
            else:
                # Multi-byte command → length determined after subcmd
                self.CommandDone = False
                self.ExpectedVMCLength = 0  # unknown yet

            cmd_name = self.COMMAND_NAMES.get(data, f"CMD_0x{data:02X}")
            target = self._get_device(data)

            if data in (0x12, 0x0B, 0x33):
                print(f"VMC→{target}: {cmd_name}")
                return AnalyzerFrame('vmc_poll', frame.start_time, frame.end_time, {'target': target})

            print(f"VMC→{target}: {cmd_name}")
            return AnalyzerFrame('vmc_cmd', frame.start_time, frame.end_time, {
                'target': target, 'command': cmd_name
            })

        # ── mode=0: data / checksum / ACK ──

        # ACK only when command is complete (checksum already sent)
        if self.CommandDone and data == 0x00:
            print("→ ACK")
            return AnalyzerFrame('per_ack', frame.start_time, frame.end_time, {})

        # Data byte
        self.ByteCount += 1
        self.DataBuffer.append(data)

        # First data byte (subcmd) → determine expected length
        if self.ByteCount == 1 and self.ExpectedVMCLength == 0:
            key = (self.PrevCommand, data)
            self.ExpectedVMCLength = self.VMC_CMD_LENGTHS.get(key, 99)

        # Reached expected length → this byte is checksum
        if self.ExpectedVMCLength > 0 and self.ByteCount == self.ExpectedVMCLength:
            self.CommandDone = True
            print(f"  CHK: 0x{data:02X}")
            return AnalyzerFrame('vmc_chk', frame.start_time, frame.end_time, {'hex_val': f"{data:02X}"})

        return self._vmc_parse_data(data, frame)

    def _vmc_parse_data(self, data, frame):
        """Parse VMC command data bytes based on command type."""
        cmd = self.PrevCommand
        pos = self.ByteCount
        target = self._get_device(cmd)
        buf = self.DataBuffer

        # ── VEND (0x13) ──
        if cmd == 0x13:
            if pos == 1:
                sub = self.VEND_SUB.get(data, f"SUB_0x{data:02X}")
                print(f"  VEND → {sub}")
                return AnalyzerFrame('vmc_subcmd', frame.start_time, frame.end_time, {
                    'target': target, 'command': 'VEND', 'sub': sub
                })
            if buf[0] == 0x00:  # VEND_REQUEST
                if pos == 3:
                    raw = (buf[1] << 8) | data
                    return self._vf(f"Price: {self._format_price(raw)} (raw={raw})", frame)
                if pos == 5:
                    return self._vf(f"Item#: {(buf[3] << 8) | data}", frame)
            if buf[0] == 0x02 and pos == 3:
                return self._vf(f"SUCCESS Item#: {(buf[1] << 8) | data}", frame)
            if buf[0] == 0x05:  # CASH_SALE
                if pos == 3:
                    raw = (buf[1] << 8) | data
                    return self._vf(f"CASH Price: {self._format_price(raw)} (raw={raw})", frame)
                if pos == 5:
                    return self._vf(f"CASH Item#: {(buf[3] << 8) | data}", frame)
            return self._vf(f"VEND[{pos}]: {self._chr_display(data)}", frame)

        # ── SETUP (0x11) ──
        if cmd == 0x11:
            if pos == 1:
                sub = self.SETUP_SUB.get(data, f"SUB_0x{data:02X}")
                print(f"  SETUP → {sub}")
                return AnalyzerFrame('vmc_subcmd', frame.start_time, frame.end_time, {
                    'target': target, 'command': 'SETUP', 'sub': sub
                })
            if buf[0] == 0x01:  # MAX_MIN_PRICES
                if pos == 3:
                    raw = (buf[1] << 8) | data
                    return self._vf(f"Max Price: {self._format_price(raw)} (raw={raw})", frame)
                if pos == 5:
                    raw = (buf[3] << 8) | data
                    return self._vf(f"Min Price: {self._format_price(raw)} (raw={raw})", frame)
            return self._vf(f"SETUP[{pos}]: {self._chr_display(data)}", frame)

        # ── READER (0x14) ──
        if cmd == 0x14:
            if pos == 1:
                sub = self.READER_SUB.get(data, f"SUB_0x{data:02X}")
                print(f"  READER → {sub}")
                return AnalyzerFrame('vmc_subcmd', frame.start_time, frame.end_time, {
                    'target': target, 'command': 'READER', 'sub': sub
                })
            return self._vf(f"READER[{pos}]: {self._chr_display(data)}", frame)

        # ── EXPANSION (0x17) ──
        if cmd == 0x17:
            if pos == 1:
                sub = self.EXPANSION_SUB.get(data, f"SUB_0x{data:02X}")
                print(f"  EXPANSION → {sub}")
                return AnalyzerFrame('vmc_subcmd', frame.start_time, frame.end_time, {
                    'target': target, 'command': 'EXPANSION', 'sub': sub
                })
            if buf[0] == 0x00:  # REQUEST_ID: mfg(3) + serial(12) + model(12) + sw(2)
                if 1 < pos <= 4:
                    return self._vf(f"Mfg[{pos-1}]: {self._chr_display(data)}", frame)
                if 4 < pos <= 16:
                    return self._vf(f"Serial[{pos-4}]: {self._chr_display(data)}", frame)
                if 16 < pos <= 28:
                    return self._vf(f"Model[{pos-16}]: {self._chr_display(data)}", frame)
                if pos <= 30:
                    return self._vf(f"SW Ver[{pos-28}]: {data}", frame)
            return self._vf(f"EXP[{pos}]: {self._chr_display(data)}", frame)

        # ── COIN_TYPE (0x0C) / BILL_TYPE (0x34) ──
        if cmd in (0x0C, 0x34):
            if pos == 2: return self._vf(f"Enable: 0x{(buf[0] << 8) | data:04X}", frame)
            if pos == 4: return self._vf(f"Manual: 0x{(buf[2] << 8) | data:04X}", frame)

        # ── BILL_ESCROW (0x35) ──
        if cmd == 0x35 and pos == 1:
            action = "STACK" if data == 0x01 else "RETURN" if data == 0x00 else f"0x{data:02X}"
            return self._vf(f"Escrow: {action}", frame)

        cmd_name = self.COMMAND_NAMES.get(cmd, f"0x{cmd:02X}")
        return self._vf(f"{cmd_name}[{pos}]: {self._chr_display(data)}", frame)

    def _vf(self, desc, frame):
        """Create VMC data frame with terminal output."""
        print(f"  {desc}")
        return AnalyzerFrame('vmc_data', frame.start_time, frame.end_time, {'description': desc})

    # ═══════════════════════════════════════════════════════════════════
    #                      PERIPHERAL CHANNEL
    # ═══════════════════════════════════════════════════════════════════
    #
    #  mode=0 → Response data byte (accumulate and parse)
    #  mode=1, data=0x00 → ACK (end of response)
    #  mode=1, data=0xFF → NAK
    #  mode=1, other → Checksum byte (end of response)
    #

    def _peripheral_decode(self, data, mode_bit, frame):
        """Peripheral TX channel."""

        # ── Mode=1: ACK / NAK / Checksum ──
        if mode_bit == 1:
            # Buffer not empty → this byte is checksum (end of response)
            if self.ResponseBuffer:
                self._finalize_response()
                self.ResponseBuffer = []
                self.ByteCount = 0
                print(f"  CHK: 0x{data:02X}")
                return AnalyzerFrame('per_chk', frame.start_time, frame.end_time, {'hex_val': f"{data:02X}"})

            # Buffer empty + data=0x00 → ACK
            if data == 0x00:
                print(f"{self.DeviceName}: ACK")
                return AnalyzerFrame('per_ack', frame.start_time, frame.end_time, {})

            # Buffer empty + data=0xFF → NAK
            if data == 0xFF:
                print(f"{self.DeviceName}: NAK")
                return AnalyzerFrame('per_nak', frame.start_time, frame.end_time, {})

            # Buffer empty + other mode=1 → unexpected
            return AnalyzerFrame('per_data', frame.start_time, frame.end_time,
                                 {'description': f"mode1: 0x{data:02X}"})

        # ── Mode=0: Data byte ──
        self.ByteCount += 1
        self.ResponseBuffer.append(data)
        return self._parse_peripheral(data, frame)

    def _get_response_summary(self):
        """Generate summary from accumulated response buffer."""
        if not self.ResponseBuffer:
            return None
        buf = self.ResponseBuffer
        dev = self.DeviceName

        if dev == "Cashless":
            resp_name = self.POLL_RESPONSE.get(buf[0], f"0x{buf[0]:02X}")
            if buf[0] == 0x03 and len(buf) >= 3:
                raw = (buf[1] << 8) | buf[2]
                return f"BEGIN_SESSION Balance={self._format_price(raw)} (raw={raw})"
            if buf[0] == 0x05 and len(buf) >= 3:
                raw = (buf[1] << 8) | buf[2]
                return f"VEND_APPROVED Amount={self._format_price(raw)} (raw={raw})"
            if buf[0] == 0x09 and len(buf) >= 28:
                mfg = ''.join([chr(b) for b in buf[1:4] if 32 <= b <= 126])
                serial = ''.join([chr(b) for b in buf[4:16] if 32 <= b <= 126])
                model = ''.join([chr(b) for b in buf[16:28] if 32 <= b <= 126])
                return f"ID:{mfg} SN:{serial} Model:{model}"
            return resp_name
        return f"{len(buf)} byte"

    def _finalize_response(self):
        """Finalize response at checksum + print summary."""
        if not self.ResponseBuffer:
            return
        summary = self._get_response_summary()
        if summary:
            print(f"  ═ {self.DeviceName}: {summary}")

    def _parse_peripheral(self, data, frame):
        """Route peripheral data to device-specific parser."""
        dev = self.DeviceName
        if dev == "Cashless":
            return self._cashless_response(data, frame)
        if dev == "Coin":
            return self._coin_response(data, frame)
        if dev == "Bill":
            return self._bill_response(data, frame)
        return self._pf(f"data[{self.ByteCount}]: {self._chr_display(data)}", frame)

    # ─── Cashless Response ─────────────────────────────────────────────

    def _cashless_response(self, data, frame):
        pos = self.ByteCount
        buf = self.ResponseBuffer
        dev = self.DeviceName

        # First byte = response code
        if pos == 1:
            resp_name = self.POLL_RESPONSE.get(data, f"RESP_0x{data:02X}")
            print(f"{dev}: {resp_name}")

            # Single-byte responses
            if data == 0x00:
                return AnalyzerFrame('per_just_reset', frame.start_time, frame.end_time, {'device': dev})
            if data == 0x04:
                return AnalyzerFrame('per_session_cancel', frame.start_time, frame.end_time, {'device': dev})
            if data == 0x06:
                return AnalyzerFrame('per_vend_denied', frame.start_time, frame.end_time, {'device': dev})
            if data == 0x07:
                return AnalyzerFrame('per_end_session', frame.start_time, frame.end_time, {'device': dev})
            if data == 0x08:
                return AnalyzerFrame('per_cancelled', frame.start_time, frame.end_time, {'device': dev})
            if data == 0x0B:
                return AnalyzerFrame('per_cmd_out_seq', frame.start_time, frame.end_time, {'device': dev})
            return self._pf(resp_name, frame)

        code = buf[0]

        # BEGIN_SESSION (0x03): code + balanceH + balanceL
        if code == 0x03:
            if pos == 3:
                raw = (buf[1] << 8) | data
                formatted = self._format_price(raw)
                return AnalyzerFrame('per_begin_session', frame.start_time, frame.end_time, {
                    'device': dev, 'balance': f"{formatted} (raw={raw})"
                })
            return self._pf(f"BEGIN[{pos}]: {self._chr_display(data)}", frame)

        # VEND_APPROVED (0x05): code + amountH + amountL
        if code == 0x05:
            if pos == 3:
                raw = (buf[1] << 8) | data
                formatted = self._format_price(raw)
                return AnalyzerFrame('per_vend_approved', frame.start_time, frame.end_time, {
                    'device': dev, 'amount': f"{formatted} (raw={raw})"
                })
            return self._pf(f"APPROVED[{pos}]: {self._chr_display(data)}", frame)

        # READER_CONFIG (0x01): level, countryH, countryL, scale, decimal, max_resp, misc, opt
        if code == 0x01:
            fields = {
                2: "Feature Level", 3: "Country H", 5: "Scale Factor",
                6: "Decimal Places", 7: "Max Response", 8: "Misc Options"
            }
            if pos == 4:
                country = (buf[2] << 8) | data
                return self._pf(f"Country: 0x{country:04X}", frame)
            if pos == 5:
                # Learn scale factor from config
                self.ScaleFactor = data
                print(f"  [Learned] Scale Factor = {data}")
                return self._pf(f"Scale Factor: {data}", frame)
            if pos == 6:
                # Learn decimal places from config
                self.DecimalPlaces = data
                print(f"  [Learned] Decimal Places = {data}")
                return self._pf(f"Decimal Places: {data}", frame)
            if pos == 9:
                return AnalyzerFrame('per_reader_config', frame.start_time, frame.end_time, {
                    'device': dev, 'level': buf[1],
                    'country': f"0x{(buf[2] << 8) | buf[3]:04X}",
                    'scale': buf[4], 'decimal': buf[5]
                })
            if pos in fields:
                return self._pf(f"{fields[pos]}: {data}", frame)
            return self._pf(f"CONFIG[{pos}]: {self._chr_display(data)}", frame)

        # DISPLAY_REQ (0x02)
        if code == 0x02:
            if pos == 2:
                return AnalyzerFrame('per_display_req', frame.start_time, frame.end_time, {
                    'device': dev, 'duration': f"{data * 0.1:.1f}"
                })
            return self._pf(f"Disp: {self._chr_display(data)}", frame)

        # PERIPHERAL_ID (0x09): mfg(3) + serial(12) + model(12) + sw(2) = 29 data bytes
        if code == 0x09:
            if pos <= 4:
                return self._pf(f"Mfg[{pos-1}]: {self._chr_display(data)}", frame)
            if pos <= 16:
                return self._pf(f"Serial[{pos-4}]: {self._chr_display(data)}", frame)
            if pos <= 28:
                return self._pf(f"Model[{pos-16}]: {self._chr_display(data)}", frame)
            if pos == 29:
                return self._pf(f"SW Ver H: {data}", frame)
            if pos == 30:
                mfg = ''.join([chr(b) for b in buf[1:4] if 32 <= b <= 126])
                serial = ''.join([chr(b) for b in buf[4:16] if 32 <= b <= 126])
                model = ''.join([chr(b) for b in buf[16:28] if 32 <= b <= 126])
                print(f"  ═ ID: {mfg} | SN:{serial} | Model:{model}")
                return AnalyzerFrame('per_peripheral_id', frame.start_time, frame.end_time, {
                    'device': dev, 'manufacturer': mfg, 'serial': serial, 'model': model
                })
            return self._pf(f"ID[{pos}]: {self._chr_display(data)}", frame)

        # MALFUNCTION (0x0A)
        if code == 0x0A and pos == 2:
            error_codes = {0x00: "General", 0x10: "Comms", 0x20: "Pay", 0x30: "Refund", 0x40: "Media"}
            error = error_codes.get(data & 0xF0, f"0x{data:02X}")
            return AnalyzerFrame('per_malfunction', frame.start_time, frame.end_time, {
                'device': dev, 'error': error
            })

        return self._pf(f"resp[{pos}]: {self._chr_display(data)}", frame)

    # ─── Coin Changer Response ─────────────────────────────────────────

    def _coin_response(self, data, frame):
        pos = self.ByteCount
        if pos == 1:
            if data & 0x80:
                route = (data >> 4) & 0x07
                coin_type = data & 0x0F
                routes = {0: "Cashbox", 1: "Tube", 2: "Reject"}
                return AnalyzerFrame('coin_deposited', frame.start_time, frame.end_time, {
                    'type': coin_type, 'route': routes.get(route, f"R{route}")
                })
            if data & 0x40:
                return AnalyzerFrame('coin_status', frame.start_time, frame.end_time, {
                    'status': f"DISPENSED Type={(data >> 4) & 0x03} Count={data & 0x0F}"
                })
            statuses = {
                0x01: "Escrow", 0x02: "Payout Busy", 0x03: "No Credit",
                0x05: "Double Arrival", 0x06: "Unplugged", 0x08: "ROM Error",
                0x0B: "Reset", 0x0C: "Coin Jam",
            }
            return AnalyzerFrame('coin_status', frame.start_time, frame.end_time, {
                'status': statuses.get(data, f"0x{data:02X}")
            })
        return self._pf(f"Coin[{pos}]: {self._chr_display(data)}", frame)

    # ─── Bill Validator Response ───────────────────────────────────────

    def _bill_response(self, data, frame):
        pos = self.ByteCount
        if pos == 1:
            if data & 0x80:
                route = (data >> 4) & 0x07
                bill_type = data & 0x0F
                routes = {0: "STACKED", 1: "ESCROW", 2: "RETURNED", 3: "RECYCLER", 4: "REJECTED"}
                return AnalyzerFrame('bill_event', frame.start_time, frame.end_time, {
                    'event': routes.get(route, f"R{route}"), 'type': bill_type
                })
            statuses = {
                0x01: "Motor Fault", 0x02: "Sensor", 0x03: "Busy",
                0x05: "Jam", 0x06: "Reset", 0x08: "Stacker Full", 0x0B: "Rejected",
            }
            return AnalyzerFrame('bill_status', frame.start_time, frame.end_time, {
                'status': statuses.get(data, f"0x{data:02X}")
            })
        return self._pf(f"Bill[{pos}]: {self._chr_display(data)}", frame)

    # ─── Helper ────────────────────────────────────────────────────────

    def _pf(self, desc, frame):
        """Create peripheral data frame with terminal output."""
        print(f"  {desc}")
        return AnalyzerFrame('per_data', frame.start_time, frame.end_time, {'description': desc})