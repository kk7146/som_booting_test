from scapy.all import sniff, ICMP, IP
from gpiozero import OutputDevice
from datetime import datetime
import threading
import signal
import sys
import os
import logging

GPIO_PIN = 17
SOM_IP = None

PULSE_SEC = 1.0
DELAY_BEFORE_PULSE_SEC = 10.0
SECOND_PULSE_DELAY_SEC = 120.0
ALARM_SEC = 7 * 60

out = OutputDevice(GPIO_PIN, active_high=True, initial_value=False)

last_ping_time = None
last_accept_time = None

alarm_timer = None
off_timer = None
delay_pulse_timer = None
second_pulse_timer = None

counter = 0
lock = threading.Lock()

PROGRAM_START_DT = datetime.now()
LOG_DATE_DIR = PROGRAM_START_DT.strftime("%Y%m%d")
LOG_FILE_TS = PROGRAM_START_DT.strftime("%Y%m%d_%H%M%S")

LOG_ROOT = "./logs"
LOG_DIR = os.path.join(LOG_ROOT, LOG_DATE_DIR)
os.makedirs(LOG_DIR, exist_ok=True)

LOG_PATH = os.path.join(LOG_DIR, f"{LOG_FILE_TS}.log")

logger = logging.getLogger("ping_gpio")
logger.setLevel(logging.INFO)

fmt = logging.Formatter("[%(asctime)s] %(message)s")

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(fmt)

fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
fh.setLevel(logging.INFO)
fh.setFormatter(fmt)

logger.handlers.clear()
logger.addHandler(ch)
logger.addHandler(fh)

def cancel_timers():
    global alarm_timer, off_timer, delay_pulse_timer, second_pulse_timer
    for t in (alarm_timer, off_timer, delay_pulse_timer, second_pulse_timer):
        if t and t.is_alive():
            t.cancel()
    alarm_timer = off_timer = delay_pulse_timer = second_pulse_timer = None

def pulse_low_then_high(reason: str):
    global off_timer
    out.off()
    logger.info(f"[{datetime.now()}] {reason}")
    logger.info(f"[{datetime.now()}] GPIO LOW")

    if off_timer and off_timer.is_alive():
        off_timer.cancel()

    def _set_high():
        out.on()
        logger.info(f"[{datetime.now()}] GPIO HIGH")

    off_timer = threading.Timer(PULSE_SEC, _set_high)
    off_timer.daemon = True
    off_timer.start()

def delayed_pulse_10s():
    pulse_low_then_high("Delayed pulse (+10s)")

def delayed_pulse_120s():
    pulse_low_then_high("Delayed pulse (+120s)")

def check_no_ping():
    with lock:
        ts = last_accept_time
    if ts is not None:
        logger.info(f"[{datetime.now()}] WARNING: No ping")

def on_ping(pkt):
    global last_ping_time, last_accept_time
    global delay_pulse_timer, second_pulse_timer, alarm_timer
    global counter

    if ICMP not in pkt or pkt[ICMP].type != 8:
        return
    if SOM_IP and pkt[IP].src != SOM_IP:
        return

    now = datetime.now()

    with lock:
        last_ping_time = now
        if last_accept_time is not None:
            if (now - last_accept_time).total_seconds() < DELAY_BEFORE_PULSE_SEC:
                return

        last_accept_time = now
        logger.info(f"[{now}] First ping accepted from {pkt[IP].src}")

        counter += 1
        logger.info(f"[{now}] Ping count: {counter}")

        if delay_pulse_timer and delay_pulse_timer.is_alive():
            delay_pulse_timer.cancel()
        if second_pulse_timer and second_pulse_timer.is_alive():
            second_pulse_timer.cancel()

        delay_pulse_timer = threading.Timer(DELAY_BEFORE_PULSE_SEC, delayed_pulse_10s)
        delay_pulse_timer.daemon = True
        delay_pulse_timer.start()

        second_pulse_timer = threading.Timer(SECOND_PULSE_DELAY_SEC, delayed_pulse_120s)
        second_pulse_timer.daemon = True
        second_pulse_timer.start()

    if alarm_timer and alarm_timer.is_alive():
        alarm_timer.cancel()
    alarm_timer = threading.Timer(ALARM_SEC, check_no_ping)
    alarm_timer.daemon = True
    alarm_timer.start()

def cleanup(*_):
    cancel_timers()
    out.off()
    logger.info(f"[{datetime.now()}] Exiting")
    sys.exit(0)

def main():
    print("Sniffing ICMP echo requests...")
    logger.info(f"[{datetime.now()}] Log file: {LOG_PATH}")

    out.on()

    bpf = "icmp and icmp[icmptype] = icmp-echo"
    if SOM_IP:
        bpf += f" and src host {SOM_IP}"

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    sniff(filter=bpf, prn=on_ping, store=False)

if __name__ == "__main__":
    main()
