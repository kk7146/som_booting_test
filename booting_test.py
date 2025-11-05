from scapy.all import sniff, ICMP, IP
from gpiozero import OutputDevice
from datetime import datetime
import threading
import signal
import sys

GPIO_PIN = 17
SOM_IP = None

PULSE_SEC = 1.0
REPULSE_DELAY_SEC = 3 * 60
ALARM_SEC = 7 * 60

out = OutputDevice(GPIO_PIN, active_high=True, initial_value=False)

last_ping_time = None
alarm_timer = None
off_timer = None
repulse_timer = None
lock = threading.Lock()

def cancel_timers():
    global alarm_timer, off_timer, repulse_timer
    for t in (alarm_timer, off_timer, repulse_timer):
        if t and t.is_alive():
            t.cancel()
    alarm_timer = None
    off_timer = None
    repulse_timer = None

def pulse_high_then_low(reason: str):
    global off_timer
    out.off()
    print(f"[{datetime.now()}] {reason}: GPIO LOW")

    if off_timer and off_timer.is_alive():
        off_timer.cancel()

    off_timer = threading.Timer(PULSE_SEC, lambda: (out.on(), print(f"[{datetime.now()}] GPIO HIGH")))
    off_timer.daemon = True
    off_timer.start()

def schedule_repulse():
    global repulse_timer
    if repulse_timer and repulse_timer.is_alive():
        repulse_timer.cancel()
    repulse_timer = threading.Timer(REPULSE_DELAY_SEC, lambda: pulse_high_then_low("Repulse ({REPULSE_DELAY_SEC} SEC)"))
    repulse_timer.daemon = True
    repulse_timer.start()

def check_no_ping():
    with lock:
        ts = last_ping_time
    if ts is not None:
        print(f"[{datetime.now()}] WARNING: No ping for {ALARM_SEC / 60:.0f} minutes since {ts}")

def on_ping(pkt):
    global last_ping_time, alarm_timer
    if ICMP in pkt and pkt[ICMP].type == 8:
        if SOM_IP and pkt[IP].src != SOM_IP:
            return

        with lock:
            last_ping_time = datetime.now()

        pulse_high_then_low(f"Ping from {pkt[IP].src}")

        schedule_repulse()

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
