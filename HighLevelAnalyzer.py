# MDB Protocol Decoder v11 - FSM-Based Architecture
# Supported: Cashless (0x10-0x17), Coin Changer (0x08-0x0F), Bill Validator (0x30-0x37)
# Author: Taymur
# Architecture: Explicit FSM with accumulate-then-decode pattern
# VMC channel:  mode=1 → command, mode=0 → data/checksum/ACK
# Peripheral:   mode=0 → response data, mode=1 → ACK/NAK/Checksum
import enum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting


class Hla(HighLevelAnalyzer):
    """
    MDB (Multi-Drop Bus) Protocol Decoder - v11
    FSM-based with accumulate-then-decode for deterministic parsing.
    """

    # ─── User Settings ─────────────────────────────────────────────────

    KanalTipi = ChoicesSetting(
        label='Channel Type',
        choices=('VMC (Command Sender)', 'Cashless (Payment Device)', 'Coin Changer', 'Bill Validator')
    )

    # ─── FSM States ────────────────────────────────────────────────────

    class State(enum.Enum):
        IDLE = 0         # Waiting for new command or response
        VMC_DATA = 1     # Accumulating VMC command data bytes
        PER_DATA = 2     # Accumulating peripheral response bytes

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

    # Single-checksum VMC commands (command byte + 1 checksum byte only)
    VMC_SINGLE_CHK = {0x08, 0x09, 0x0A, 0x0B, 0x10, 0x12, 0x30, 0x31, 0x33, 0x36}

    # VMC command + subcmd → total data bytes (including checksum)
    VMC_CMD_LENGTHS = {
        (0x13, 0x00): 6, (0x13, 0x01): 2, (0x13, 0x02): 4,
        (0x13, 0x03): 2, (0x13, 0x04): 2, (0x13, 0x05): 6,
        (0x11, 0x00): 5, (0x11, 0x01): 6,
        (0x14, 0x00): 2, (0x14, 0x01): 2, (0x14, 0x02): 2,
        (0x17, 0x00): 31, (0x17, 0x04): 6,
        (0x15, 0x00): 4, (0x15, 0x01): 2,
    }
    VMC_FIXED_LENGTHS = {0x0C: 5, 0x34: 5, 0x35: 2, 0x32: 3}

    # Commands whose POLL/ACK should not spam the terminal
    POLL_COMMANDS = {0x12, 0x0B, 0x33}

    # ─── Saleae Frame Types ────────────────────────────────────────────

    result_types = {
        'vmc_cmd':      {'format': 'VMC→{data.target}: {data.command}'},
        'vmc_subcmd':   {'format': '  → {data.sub}'},
        'vmc_data':     {'format': '  {data.description}'},
        'vmc_poll':     {'format': 'VMC→{data.target}: POLL'},
        'vmc_chk':      {'format': 'CHK: 0x{data.hex_val}'},
        'vmc_summary':  {'format': '{data.summary}'},
        'per_ack':      {'format': '→ ACK'},
        'per_nak':      {'format': '✗ NAK'},
        'per_chk':      {'format': 'CHK: 0x{data.hex_val}'},
        'per_just_reset':    {'format': '{data.device}: JUST RESET'},
        'per_begin_session': {'format': '{data.device}: BEGIN SESSION Balance={data.balance}'},
        'per_vend_approved': {'format': '{data.device}: VEND APPROVED Amount={data.amount}'},
        'per_vend_denied':   {'format': '{data.device}: VEND DENIED'},
        'per_end_session':   {'format': '{data.device}: END SESSION'},
        'per_session_cancel':{'format': '{data.device}: SESSION CANCEL'},
        'per_cancelled':     {'format': '{data.device}: CANCELLED'},
        'per_reader_config': {'format': '{data.device}: CONFIG L{data.level} Country={data.country} Scale={data.scale} Decimal={data.decimal}'},
        'per_display_req':   {'format': '{data.device}: DISPLAY {data.duration}s'},
        'per_peripheral_id': {'format': '{data.device}: {data.manufacturer} SN:{data.serial} Model:{data.model}'},
        'per_malfunction':   {'format': '{data.device}: FAULT {data.error}'},
        'per_cmd_out_seq':   {'format': '{data.device}: CMD OUT OF SEQ'},
        'per_data':     {'format': '  {data.description}'},
        'per_summary':  {'format': '{data.summary}'},
        'coin_deposited': {'format': 'Coin: DEPOSIT Type={data.type} Route={data.route}'},
        'coin_status':    {'format': 'Coin: {data.status}'},
        'bill_event':     {'format': 'Bill: {data.event} Type={data.type}'},
        'bill_status':    {'format': 'Bill: {data.status}'},
        'mdb_data':       {'format': '{data.hex_val}'},
    }

    # ─── Initialization ────────────────────────────────────────────────

    def __init__(self):
        # FSM state
        self.state = self.State.IDLE

        # VMC state
        self.vmc_command = 0x00       # Current command byte
        self.vmc_buffer = []          # Accumulated data bytes
        self.vmc_expected_len = 0     # Expected data byte count
        self.vmc_cmd_start = None     # Timestamp: command start
        self.vmc_is_poll = False      # Is this a POLL command?

        # Peripheral state
        self.per_buffer = []          # Accumulated response bytes
        self.per_start = None         # Timestamp: response start

        # Price calculation (learned from READER_CONFIG)
        self.scale_factor = 1
        self.decimal_places = 0

        # Channel detection
        self.is_vmc = 'VMC' in self.KanalTipi
        self.device_name = "VMC"
        if 'Cashless' in self.KanalTipi:
            self.device_name = "Cashless"
        elif 'Coin' in self.KanalTipi:
            self.device_name = "Coin"
        elif 'Bill' in self.KanalTipi:
            self.device_name = "Bill"

    def _reset_state(self):
        """Clean reset of ALL state variables → IDLE."""
        self.state = self.State.IDLE
        self.vmc_command = 0x00
        self.vmc_buffer = []
        self.vmc_expected_len = 0
        self.vmc_cmd_start = None
        self.vmc_is_poll = False
        self.per_buffer = []
        self.per_start = None

    # ─── Helpers ───────────────────────────────────────────────────────

    def _get_device(self, cmd):
        return self.DEVICE_NAMES.get(cmd >> 3, f"0x{cmd:02X}")

    def _chr(self, v):
        if 32 <= v <= 126:
            return f"'{chr(v)}' (0x{v:02X})"
        return f"0x{v:02X}"

    def _format_price(self, raw):
        """Format raw MDB price using learned scale factor and decimal places."""
        actual = raw * self.scale_factor
        if self.decimal_places > 0:
            divisor = 10 ** self.decimal_places
            return f"{actual / divisor:.{self.decimal_places}f}"
        return str(actual)

    # ═══════════════════════════════════════════════════════════════════
    #                        MAIN DECODE
    # ═══════════════════════════════════════════════════════════════════

    def decode(self, frame: AnalyzerFrame):
        if frame.type != 'data':
            return None
        raw = frame.data['data']
        if len(raw) < 2:
            return AnalyzerFrame('mdb_data', frame.start_time, frame.end_time,
                                 {'hex_val': f"0x{raw[0]:02X}"})

        mode_bit = 1 if (raw[0] & 0x01) else 0
        data = raw[1]

        if self.is_vmc:
            return self._vmc_decode(data, mode_bit, frame)
        else:
            return self._peripheral_decode(data, mode_bit, frame)

    # ═══════════════════════════════════════════════════════════════════
    #                       VMC CHANNEL FSM
    # ═══════════════════════════════════════════════════════════════════

    def _vmc_decode(self, data, mode_bit, frame):
        """
        VMC TX FSM:
          IDLE + mode=1 → new command → VMC_DATA
          IDLE + mode=0 + 0x00 → ACK (to peripheral)
          VMC_DATA + mode=0 → accumulate data
          VMC_DATA + reached expected length → checksum → IDLE
          Any + mode=1 → reset + new command (error recovery)
        """

        # ── mode=1: ALWAYS starts a new command (error recovery built-in) ──
        if mode_bit:
            # If we were mid-command, that command is lost — reset cleanly
            self.state = self.State.VMC_DATA
            self.vmc_command = data
            self.vmc_buffer = []
            self.vmc_cmd_start = frame.start_time
            self.vmc_is_poll = data in self.POLL_COMMANDS

            # Determine expected data length
            if data in self.VMC_SINGLE_CHK:
                self.vmc_expected_len = 1
            elif data in self.VMC_FIXED_LENGTHS:
                self.vmc_expected_len = self.VMC_FIXED_LENGTHS[data]
            else:
                self.vmc_expected_len = 0  # Unknown until subcmd

            cmd_name = self.COMMAND_NAMES.get(data, f"CMD_0x{data:02X}")
            target = self._get_device(data)

            # Terminal: only print non-POLL commands
            if not self.vmc_is_poll:
                print(f"VMC→{target}: {cmd_name}")

            if self.vmc_is_poll:
                return AnalyzerFrame('vmc_poll', frame.start_time, frame.end_time, {'target': target})
            return AnalyzerFrame('vmc_cmd', frame.start_time, frame.end_time, {
                'target': target, 'command': cmd_name
            })

        # ── mode=0: data / checksum / ACK ──

        # IDLE + 0x00 → ACK (VMC acknowledging peripheral response)
        if self.state == self.State.IDLE:
            if data == 0x00:
                return AnalyzerFrame('per_ack', frame.start_time, frame.end_time, {})
            # Unexpected data in IDLE — show it but stay IDLE
            return AnalyzerFrame('vmc_data', frame.start_time, frame.end_time, {
                'description': f"unexpected: 0x{data:02X}"
            })

        # VMC_DATA: accumulate
        self.vmc_buffer.append(data)
        pos = len(self.vmc_buffer)

        # First data byte of multi-byte command → determine length from subcmd
        if pos == 1 and self.vmc_expected_len == 0:
            key = (self.vmc_command, data)
            self.vmc_expected_len = self.VMC_CMD_LENGTHS.get(key, 99)

        # Reached expected length → this byte is checksum → decode complete message
        if self.vmc_expected_len > 0 and pos == self.vmc_expected_len:
            result = self._vmc_complete(frame)
            self.state = self.State.IDLE
            return result

        # Still accumulating — return per-byte frame for timeline
        return self._vmc_byte_frame(data, pos, frame)

    def _vmc_byte_frame(self, data, pos, frame):
        """Generate per-byte timeline frame during accumulation."""
        cmd = self.vmc_command
        buf = self.vmc_buffer
        target = self._get_device(cmd)

        # First byte is subcmd for multi-byte commands
        if pos == 1 and cmd not in self.VMC_SINGLE_CHK and cmd not in self.VMC_FIXED_LENGTHS:
            sub_table = {0x13: self.VEND_SUB, 0x11: self.SETUP_SUB,
                         0x14: self.READER_SUB, 0x17: self.EXPANSION_SUB}
            table = sub_table.get(cmd, {})
            sub = table.get(data, f"SUB_0x{data:02X}")
            print(f"  → {sub}")
            return AnalyzerFrame('vmc_subcmd', frame.start_time, frame.end_time, {
                'target': target, 'command': self.COMMAND_NAMES.get(cmd, '?'), 'sub': sub
            })

        # Generic data byte
        desc = f"{self.COMMAND_NAMES.get(cmd, '?')}[{pos}]: {self._chr(data)}"
        return AnalyzerFrame('vmc_data', frame.start_time, frame.end_time, {'description': desc})

    def _vmc_complete(self, frame):
        """Decode complete VMC command at checksum boundary."""
        cmd = self.vmc_command
        buf = self.vmc_buffer
        chk = buf[-1]  # Last byte is checksum
        data_bytes = buf[:-1]  # Everything except checksum
        target = self._get_device(cmd)
        cmd_name = self.COMMAND_NAMES.get(cmd, f"0x{cmd:02X}")

        # Single-checksum commands (POLL, RESET, etc.) — just the checksum frame
        if cmd in self.VMC_SINGLE_CHK:
            return AnalyzerFrame('vmc_chk', frame.start_time, frame.end_time, {'hex_val': f"{chk:02X}"})

        # Multi-byte commands — generate summary
        summary = self._vmc_summarize(cmd, data_bytes, target)
        if summary and not self.vmc_is_poll:
            print(f"  ▸ {summary}")
            print(f"  CHK: 0x{chk:02X}")

        return AnalyzerFrame('vmc_chk', frame.start_time, frame.end_time, {'hex_val': f"{chk:02X}"})

    def _vmc_summarize(self, cmd, data, target):
        """Generate human-readable summary of complete VMC command."""
        if not data:
            return None

        # VEND (0x13)
        if cmd == 0x13:
            sub = self.VEND_SUB.get(data[0], f"0x{data[0]:02X}")
            if data[0] == 0x00 and len(data) >= 5:  # VEND_REQUEST
                price_raw = (data[1] << 8) | data[2]
                item = (data[3] << 8) | data[4]
                return f"VEND_REQUEST Price={self._format_price(price_raw)} Item#{item}"
            if data[0] == 0x02 and len(data) >= 3:  # VEND_SUCCESS
                item = (data[1] << 8) | data[2]
                return f"VEND_SUCCESS Item#{item}"
            if data[0] == 0x05 and len(data) >= 5:  # CASH_SALE
                price_raw = (data[1] << 8) | data[2]
                item = (data[3] << 8) | data[4]
                return f"CASH_SALE Price={self._format_price(price_raw)} Item#{item}"
            return sub

        # SETUP (0x11)
        if cmd == 0x11:
            sub = self.SETUP_SUB.get(data[0], f"0x{data[0]:02X}")
            if data[0] == 0x01 and len(data) >= 5:  # MAX_MIN_PRICES
                max_raw = (data[1] << 8) | data[2]
                min_raw = (data[3] << 8) | data[4]
                return f"MAX_MIN_PRICES Max={self._format_price(max_raw)} Min={self._format_price(min_raw)}"
            return sub

        # READER (0x14)
        if cmd == 0x14:
            return self.READER_SUB.get(data[0], f"READER 0x{data[0]:02X}")

        # EXPANSION (0x17)
        if cmd == 0x17:
            if data[0] == 0x00 and len(data) >= 30:  # REQUEST_ID
                mfg = ''.join([chr(b) for b in data[1:4] if 32 <= b <= 126])
                serial = ''.join([chr(b) for b in data[4:16] if 32 <= b <= 126])
                model = ''.join([chr(b) for b in data[16:28] if 32 <= b <= 126])
                return f"REQUEST_ID Mfg={mfg} SN={serial} Model={model}"
            return self.EXPANSION_SUB.get(data[0], f"EXP 0x{data[0]:02X}")

        return None

    # ═══════════════════════════════════════════════════════════════════
    #                    PERIPHERAL CHANNEL FSM
    # ═══════════════════════════════════════════════════════════════════

    def _peripheral_decode(self, data, mode_bit, frame):
        """
        Peripheral TX FSM:
          IDLE + mode=1 + 0x00 → ACK
          IDLE + mode=1 + 0xFF → NAK
          IDLE + mode=0 → first response byte → PER_DATA
          PER_DATA + mode=0 → accumulate
          PER_DATA + mode=1 → checksum → decode complete → IDLE
        """

        # ── Mode=1: ACK / NAK / Checksum ──
        if mode_bit == 1:
            if self.state == self.State.PER_DATA and self.per_buffer:
                # Buffer has data → this is checksum (end of response)
                result = self._per_complete(data, frame)
                self.state = self.State.IDLE
                self.per_buffer = []
                self.per_start = None
                return result

            # IDLE: standalone control byte
            self.state = self.State.IDLE
            if data == 0x00:
                return AnalyzerFrame('per_ack', frame.start_time, frame.end_time, {})
            if data == 0xFF:
                print(f"{self.device_name}: NAK")
                return AnalyzerFrame('per_nak', frame.start_time, frame.end_time, {})
            # Unexpected mode=1 byte
            return AnalyzerFrame('per_data', frame.start_time, frame.end_time, {
                'description': f"mode1: 0x{data:02X}"
            })

        # ── Mode=0: Data byte → accumulate ──
        if self.state != self.State.PER_DATA:
            self.state = self.State.PER_DATA
            self.per_buffer = []
            self.per_start = frame.start_time

        self.per_buffer.append(data)
        pos = len(self.per_buffer)

        # Return per-byte frame for timeline
        return self._per_byte_frame(data, pos, frame)

    def _per_byte_frame(self, data, pos, frame):
        """Generate per-byte timeline frame for peripheral response."""
        dev = self.device_name

        if dev == "Cashless" and pos == 1:
            resp_name = self.POLL_RESPONSE.get(data, f"RESP_0x{data:02X}")
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

        if dev == "Cashless":
            return self._cashless_byte(data, pos, frame)
        if dev == "Coin":
            return self._coin_byte(data, pos, frame)
        if dev == "Bill":
            return self._bill_byte(data, pos, frame)

        return self._pf(f"data[{pos}]: {self._chr(data)}", frame)

    def _per_complete(self, chk_byte, frame):
        """Decode complete peripheral response at checksum boundary."""
        buf = self.per_buffer
        dev = self.device_name
        summary = self._per_summarize(buf, dev)

        if summary:
            print(f"  ═ {dev}: {summary}")

        print(f"  CHK: 0x{chk_byte:02X}")
        return AnalyzerFrame('per_chk', frame.start_time, frame.end_time, {'hex_val': f"{chk_byte:02X}"})

    def _per_summarize(self, buf, dev):
        """Generate human-readable summary of complete peripheral response."""
        if not buf:
            return None

        if dev == "Cashless":
            code = buf[0]
            resp_name = self.POLL_RESPONSE.get(code, f"0x{code:02X}")

            if code == 0x00:
                return "JUST_RESET"
            if code == 0x03 and len(buf) >= 3:
                raw = (buf[1] << 8) | buf[2]
                return f"BEGIN_SESSION Balance={self._format_price(raw)} (raw={raw})"
            if code == 0x05 and len(buf) >= 3:
                raw = (buf[1] << 8) | buf[2]
                return f"VEND_APPROVED Amount={self._format_price(raw)} (raw={raw})"
            if code == 0x06:
                return "VEND_DENIED"
            if code == 0x07:
                return "END_SESSION"
            if code == 0x01 and len(buf) >= 8:
                # READER_CONFIG — learn scale factor and decimal places
                self.scale_factor = buf[4]
                self.decimal_places = buf[5]
                print(f"  [Learned] Scale={buf[4]}, Decimal={buf[5]}")
                return f"READER_CONFIG Level={buf[1]} Scale={buf[4]} Decimal={buf[5]}"
            if code == 0x09 and len(buf) >= 28:
                mfg = ''.join([chr(b) for b in buf[1:4] if 32 <= b <= 126])
                serial = ''.join([chr(b) for b in buf[4:16] if 32 <= b <= 126])
                model = ''.join([chr(b) for b in buf[16:28] if 32 <= b <= 126])
                return f"ID:{mfg} SN:{serial} Model:{model}"
            return resp_name

        if dev == "Coin":
            if buf[0] & 0x80:
                route_num = (buf[0] >> 4) & 0x07
                routes = {0: "Cashbox", 1: "Tube", 2: "Reject"}
                return f"DEPOSIT Type={buf[0] & 0x0F} Route={routes.get(route_num, '?')}"
            return f"{len(buf)} byte"

        if dev == "Bill":
            if buf[0] & 0x80:
                route_num = (buf[0] >> 4) & 0x07
                routes = {0: "STACKED", 1: "ESCROW", 2: "RETURNED", 3: "RECYCLER", 4: "REJECTED"}
                return f"{routes.get(route_num, '?')} Type={buf[0] & 0x0F}"
            return f"{len(buf)} byte"

        return f"{len(buf)} byte"

    # ─── Cashless Per-Byte Decode ──────────────────────────────────────

    def _cashless_byte(self, data, pos, frame):
        """Per-byte decode for Cashless timeline bubbles."""
        buf = self.per_buffer
        dev = self.device_name
        code = buf[0]

        # BEGIN_SESSION (0x03): funds high/low
        if code == 0x03:
            if pos == 3:
                raw = (buf[1] << 8) | data
                formatted = self._format_price(raw)
                return AnalyzerFrame('per_begin_session', frame.start_time, frame.end_time, {
                    'device': dev, 'balance': f"{formatted} (raw={raw})"
                })
            return self._pf(f"BEGIN[{pos}]: 0x{data:02X}", frame)

        # VEND_APPROVED (0x05)
        if code == 0x05:
            if pos == 3:
                raw = (buf[1] << 8) | data
                formatted = self._format_price(raw)
                return AnalyzerFrame('per_vend_approved', frame.start_time, frame.end_time, {
                    'device': dev, 'amount': f"{formatted} (raw={raw})"
                })
            return self._pf(f"APPROVED[{pos}]: 0x{data:02X}", frame)

        # READER_CONFIG (0x01)
        if code == 0x01:
            fields = {2: "Feature Level", 3: "Country H", 4: "Country L",
                      5: "Scale Factor", 6: "Decimal Places", 7: "Max Response", 8: "Misc"}
            if pos == 9:
                return AnalyzerFrame('per_reader_config', frame.start_time, frame.end_time, {
                    'device': dev, 'level': buf[1],
                    'country': f"0x{(buf[2] << 8) | buf[3]:04X}",
                    'scale': buf[4], 'decimal': buf[5]
                })
            if pos in fields:
                return self._pf(f"{fields[pos]}: {data}", frame)
            return self._pf(f"CONFIG[{pos}]: 0x{data:02X}", frame)

        # DISPLAY_REQ (0x02)
        if code == 0x02 and pos == 2:
            return AnalyzerFrame('per_display_req', frame.start_time, frame.end_time, {
                'device': dev, 'duration': f"{data * 0.1:.1f}"
            })

        # PERIPHERAL_ID (0x09)
        if code == 0x09:
            if pos <= 4:
                return self._pf(f"Mfg[{pos-1}]: {self._chr(data)}", frame)
            if pos <= 16:
                return self._pf(f"Serial[{pos-4}]: {self._chr(data)}", frame)
            if pos <= 28:
                return self._pf(f"Model[{pos-16}]: {self._chr(data)}", frame)
            if pos == 29:
                return self._pf(f"SW Ver H: {data}", frame)
            if pos == 30:
                mfg = ''.join([chr(b) for b in buf[1:4] if 32 <= b <= 126])
                serial = ''.join([chr(b) for b in buf[4:16] if 32 <= b <= 126])
                model = ''.join([chr(b) for b in buf[16:28] if 32 <= b <= 126])
                return AnalyzerFrame('per_peripheral_id', frame.start_time, frame.end_time, {
                    'device': dev, 'manufacturer': mfg, 'serial': serial, 'model': model
                })
            return self._pf(f"ID[{pos}]: {self._chr(data)}", frame)

        # MALFUNCTION (0x0A)
        if code == 0x0A and pos == 2:
            errors = {0x00: "General", 0x10: "Comms", 0x20: "Pay", 0x30: "Refund", 0x40: "Media"}
            err = errors.get(data & 0xF0, f"0x{data:02X}")
            return AnalyzerFrame('per_malfunction', frame.start_time, frame.end_time, {
                'device': dev, 'error': err
            })

        return self._pf(f"resp[{pos}]: {self._chr(data)}", frame)

    # ─── Coin Per-Byte Decode ──────────────────────────────────────────

    def _coin_byte(self, data, pos, frame):
        if pos == 1:
            if data & 0x80:
                route = (data >> 4) & 0x07
                routes = {0: "Cashbox", 1: "Tube", 2: "Reject"}
                return AnalyzerFrame('coin_deposited', frame.start_time, frame.end_time, {
                    'type': data & 0x0F, 'route': routes.get(route, f"R{route}")
                })
            if data & 0x40:
                return AnalyzerFrame('coin_status', frame.start_time, frame.end_time, {
                    'status': f"DISPENSED Type={(data >> 4) & 0x03} Count={data & 0x0F}"
                })
            statuses = {0x01: "Escrow", 0x02: "Payout Busy", 0x03: "No Credit",
                        0x05: "Double Arrival", 0x06: "Unplugged", 0x08: "ROM Error",
                        0x0B: "Reset", 0x0C: "Coin Jam"}
            return AnalyzerFrame('coin_status', frame.start_time, frame.end_time, {
                'status': statuses.get(data, f"0x{data:02X}")
            })
        return self._pf(f"Coin[{pos}]: {self._chr(data)}", frame)

    # ─── Bill Per-Byte Decode ──────────────────────────────────────────

    def _bill_byte(self, data, pos, frame):
        if pos == 1:
            if data & 0x80:
                route = (data >> 4) & 0x07
                routes = {0: "STACKED", 1: "ESCROW", 2: "RETURNED", 3: "RECYCLER", 4: "REJECTED"}
                return AnalyzerFrame('bill_event', frame.start_time, frame.end_time, {
                    'event': routes.get(route, f"R{route}"), 'type': data & 0x0F
                })
            statuses = {0x01: "Motor Fault", 0x02: "Sensor", 0x03: "Busy",
                        0x05: "Jam", 0x06: "Reset", 0x08: "Stacker Full", 0x0B: "Rejected"}
            return AnalyzerFrame('bill_status', frame.start_time, frame.end_time, {
                'status': statuses.get(data, f"0x{data:02X}")
            })
        return self._pf(f"Bill[{pos}]: {self._chr(data)}", frame)

    # ─── Helper ────────────────────────────────────────────────────────

    def _pf(self, desc, frame):
        """Create peripheral data frame with terminal output."""
        print(f"  {desc}")
        return AnalyzerFrame('per_data', frame.start_time, frame.end_time, {'description': desc})