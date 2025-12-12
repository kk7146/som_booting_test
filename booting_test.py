from scapy.all import sniff, ICMP, IP
from gpiozero import OutputDevice
from datetime import datetime
import threading
import signal
import sys

GPIO_PIN = 17
SOM_IP = None

PULSE_SEC = 1.0
DELAY_BEFORE_PULSE_SEC = 10.0
SECOND_PULSE_DELAY_SEC = 120.0
REPULSE_DELAY_SEC = 3 * 60
ALARM_SEC = 7 * 60

out = OutputDevice(GPIO_PIN, active_high=True, initial_value=False)

last_ping_time = None
last_accept_time = None

alarm_timer = None
off_timer = None
repulse_timer = None
delay_pulse_timer = None
second_pulse_timer = None

counter = 0

lock = threading.Lock()

def cancel_timers():
    global alarm_timer, off_timer, repulse_timer, delay_pulse_timer, second_pulse_timer
    for t in (alarm_timer, off_timer, repulse_timer, delay_pulse_timer, second_pulse_timer):
        if t and t.is_alive():
            t.cancel()
    alarm_timer = off_timer = repulse_timer = delay_pulse_timer = second_pulse_timer = None

def pulse_low_then_high(reason: str):
    global off_timer
    out.off()
    print(f"[{datetime.now()}] {reason}")
    print(f"[{datetime.now()}] GPIO LOW")

    if off_timer and off_timer.is_alive():
        off_timer.cancel()

    off_timer = threading.Timer(
        PULSE_SEC,
        lambda: (out.on(), print(f"[{datetime.now()}] GPIO HIGH"))
    )
    off_timer.daemon = True
    off_timer.start()

def schedule_repulse():
    global repulse_timer
    if repulse_timer and repulse_timer.is_alive():
        repulse_timer.cancel()
    repulse_timer = threading.Timer(
        REPULSE_DELAY_SEC,
        lambda: pulse_low_then_high("Repulse")
    )
    repulse_timer.daemon = True
    repulse_timer.start()

def delayed_pulse_10s():
    pulse_low_then_high("Delayed pulse (+10s)")
    schedule_repulse()

def delayed_pulse_120s():
    pulse_low_then_high("Delayed pulse (+120s)")

def check_no_ping():
    with lock:
        ts = last_accept_time
    if ts is not None:
        print(f"[{datetime.now()}] WARNING: No ping")

def on_ping(pkt):
    global last_ping_time, last_accept_time
    global delay_pulse_timer, second_pulse_timer, alarm_timer

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
        print(f"[{now}] First ping accepted from {pkt[IP].src}")

        global counter
        counter += 1
        print(f"[{now}] Ping count: {counter}")

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
    sys.exit(0)

def main():
    print("Sniffing ICMP echo requests...")
    out.on()

    bpf = "icmp and icmp[icmptype] = icmp-echo"
    if SOM_IP:
        bpf += f" and src host {SOM_IP}"

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    sniff(filter=bpf, prn=on_ping, store=False)

if __name__ == "__main__":
    main()
