"""
MDB Protocol Decoder v10 - Test Script
Two-channel support: VMC and Peripheral (Cashless/Coin/Bill)
9-bit UART: Saleae frame = [CtrlByte, DataByte]
  0x112 → [0x01, 0x12] → mode=1, data=0x12
  0x012 → [0x00, 0x12] → mode=0, data=0x12
  0x100 → [0x01, 0x00] → mode=1, data=0x00 (ACK on peripheral)
  0x000 → [0x00, 0x00] → mode=0, data=0x00 (JUST_RESET / VMC ACK)
"""
import sys
import types

# ── Saleae API Mock ─────────────────────────────────────────────────

class MockAnalyzerFrame:
    def __init__(self, frame_type, start_time, end_time, data):
        self.type = frame_type
        self.start_time = start_time
        self.end_time = end_time
        self.data = data
    def __repr__(self):
        return f"Frame('{self.type}', {self.data})"

class MockHighLevelAnalyzer:
    pass

class MockChoicesSetting:
    def __init__(self, **kwargs):
        self.label = kwargs.get('label', '')
        self.choices = kwargs.get('choices', ())
    def __set_name__(self, owner, name):
        self._name = name
    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return getattr(obj, f'_setting_{self._name}', self.choices[0])
    def __set__(self, obj, value):
        setattr(obj, f'_setting_{self._name}', value)

mock_saleae = types.ModuleType('saleae')
mock_analyzers = types.ModuleType('saleae.analyzers')
mock_analyzers.HighLevelAnalyzer = MockHighLevelAnalyzer
mock_analyzers.AnalyzerFrame = MockAnalyzerFrame
mock_analyzers.ChoicesSetting = MockChoicesSetting
mock_saleae.analyzers = mock_analyzers
sys.modules['saleae'] = mock_saleae
sys.modules['saleae.analyzers'] = mock_analyzers

from HighLevelAnalyzer import Hla

# ── Helpers ──────────────────────────────────────────────────────────

def f9(hex9bit):
    """Create Saleae frame from 9-bit hex value. Ex: 0x112 → [0x01, 0x12]"""
    mode = (hex9bit >> 8) & 0x01
    data = hex9bit & 0xFF
    return MockAnalyzerFrame('data', 0.0, 1.0, {'data': bytes([mode, data])})

def new_decoder(channel):
    d = Hla.__new__(Hla)
    d.KanalTipi = channel
    d.__init__()
    return d

ok = 0; fail = 0

def test(name, decoder, frame_9bit, expected_type, expected_data=None):
    global ok, fail
    frame = f9(frame_9bit)
    result = decoder.decode(frame)
    if result is None:
        if expected_type is None:
            print(f"  ✓ {name}: None"); ok += 1; return
        print(f"  ✗ {name}: None, expected: '{expected_type}'"); fail += 1; return
    if result.type != expected_type:
        print(f"  ✗ {name}: type='{result.type}', expected='{expected_type}' data={result.data}"); fail += 1; return
    if expected_data:
        for k, v in expected_data.items():
            if result.data.get(k) != v:
                print(f"  ✗ {name}: {k}={result.data.get(k)}, expected={v}"); fail += 1; return
    print(f"  ✓ {name}: '{result.type}' {result.data}"); ok += 1

# ═══════════════════════════════════════════════════════════════════
#              VMC CHANNEL TESTS (9-bit hex values)
# ═══════════════════════════════════════════════════════════════════

print("=" * 60)
print("VMC CHANNEL TESTS")
print("=" * 60)
d = new_decoder('VMC (Command Sender)')

print("\n-- Commands (mode=1) --")
test("POLL  0x112", d, 0x112, 'vmc_poll', {'target': 'Cashless'})
test("CHK   0x012", d, 0x012, 'vmc_chk')   # Checksum after POLL
test("ACK   0x000", d, 0x000, 'per_ack')   # VMC sends ACK to peripheral

test("RESET 0x110", d, 0x110, 'vmc_cmd', {'command': 'RESET'})
test("CHK   0x010", d, 0x010, 'vmc_chk')
test("ACK   0x000", d, 0x000, 'per_ack')

print("\n-- SETUP + data --")
test("SETUP 0x111", d, 0x111, 'vmc_cmd', {'command': 'SETUP'})
test("subcmd 0x001", d, 0x001, 'vmc_subcmd', {'sub': 'MAX_MIN_PRICES'})
test("maxH  0x0FF", d, 0x0FF, 'vmc_data')
test("maxL  0x0FE", d, 0x0FE, 'vmc_data')

print("\n-- VEND REQUEST --")
test("VEND  0x113", d, 0x113, 'vmc_cmd', {'command': 'VEND'})
test("subcmd 0x000", d, 0x000, 'vmc_subcmd', {'sub': 'VEND_REQUEST'})  # 0x00 subcmd, NOT ACK!

print("\n-- COIN/BILL POLL --")
test("COIN_POLL 0x10B", d, 0x10B, 'vmc_poll', {'target': 'Coin'})
test("CHK      0x00B", d, 0x00B, 'vmc_chk')
test("BILL_POLL 0x133", d, 0x133, 'vmc_poll', {'target': 'Bill'})
test("CHK      0x033", d, 0x033, 'vmc_chk')

# ═══════════════════════════════════════════════════════════════════
#       CASHLESS CHANNEL TESTS (mode=0 → data, mode=1 → ACK/CHK)
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("CASHLESS CHANNEL TESTS")
print("=" * 60)
d = new_decoder('Cashless (Payment Device)')

print("\n-- ACK / NAK --")
test("ACK  0x100", d, 0x100, 'per_ack')    # mode=1, data=0x00 → ACK
test("NAK  0x1FF", d, 0x1FF, 'per_nak')    # mode=1, data=0xFF → NAK

print("\n-- JUST_RESET (mode=0, data=0x00) --")
test("JUST_RESET 0x000", d, 0x000, 'per_just_reset')  # mode=0, data=0x00
test("CHK        0x100", d, 0x100, 'per_chk')          # mode=1 → checksum (data=0x00)
test("ACK after ", d, 0x100, 'per_ack')                # Next mode=1 0x00 → ACK (buffer empty)

print("\n-- BEGIN_SESSION [0x03, H, L] + CHK --")
d = new_decoder('Cashless (Payment Device)')
test("code  0x003", d, 0x003, 'per_data')              # BEGIN_SESSION code
test("funH  0x001", d, 0x001, 'per_data')              # funds high
test("funL  0x0F4", d, 0x0F4, 'per_begin_session')     # funds low → balance=500
test("CHK   0x1F8", d, 0x1F8, 'per_chk')              # mode=1 → checksum

print("\n-- VEND_DENIED (single byte) --")
d = new_decoder('Cashless (Payment Device)')
test("DENIED 0x006", d, 0x006, 'per_vend_denied')      # mode=0, data=0x06
test("CHK    0x106", d, 0x106, 'per_chk')              # mode=1 → checksum

print("\n-- END_SESSION (single byte) --")
d = new_decoder('Cashless (Payment Device)')
test("END    0x007", d, 0x007, 'per_end_session')
test("CHK    0x107", d, 0x107, 'per_chk')

print("\n-- PERIPHERAL_ID full --")
d = new_decoder('Cashless (Payment Device)')
# 0x09 + "DMS" + "PAV200014104" + "UN20        " + SW[2]
id_bytes = [0x09] + [0x44, 0x4D, 0x53] + list(b'PAV200014104') + list(b'UN20        ') + [0x22, 0x25]
for i, b in enumerate(id_bytes):
    if i == len(id_bytes) - 1:
        test(f"ID[{i+1}]", d, b, 'per_peripheral_id' if i == 29 else 'per_data')
    elif i == 0:
        test(f"ID code", d, b, 'per_data')
    else:
        test(f"ID[{i+1}]", d, b, 'per_data')
test("ID CHK", d, 0x1DC, 'per_chk')  # mode=1, checksum

# ═══════════════════════════════════════════════════════════════════
#                       COIN CHANNEL TESTS
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("COIN CHANNEL TESTS")
print("=" * 60)
d = new_decoder('Coin Changer')

test("ACK   0x100", d, 0x100, 'per_ack')
test("DEPOSIT 0x083", d, 0x083, 'coin_deposited', {'type': 3, 'route': 'Cashbox'})
test("CHK    0x183", d, 0x183, 'per_chk')

# ═══════════════════════════════════════════════════════════════════
#                       BILL CHANNEL TESTS
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("BILL CHANNEL TESTS")
print("=" * 60)
d = new_decoder('Bill Validator')

test("ACK      0x100", d, 0x100, 'per_ack')
test("STACKED  0x082", d, 0x082, 'bill_event', {'event': 'STACKED', 'type': 2})
test("CHK      0x182", d, 0x182, 'per_chk')

d = new_decoder('Bill Validator')
test("REJECTED 0x00B", d, 0x00B, 'bill_status')
test("CHK      0x10B", d, 0x10B, 'per_chk')

# ── Results ──
print(f"\n{'='*60}")
print(f"RESULT: {ok}/{ok+fail} passed")
if fail == 0:
    print("ALL TESTS PASSED! ✓")
else:
    print(f"{fail} test(s) failed!")
print("=" * 60)
sys.exit(0 if fail == 0 else 1)
