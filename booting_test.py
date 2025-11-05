from scapy.all import sniff, ICMP, IP
from gpiozero import OutputDevice
from datetime import datetime
import threading
import signal
import sys

GPIO_PIN = 17
SOM_IP = None
REASSERT_SEC = 5 * 60
ALARM_SEC = 10 * 60

out = OutputDevice(GPIO_PIN, active_high=True, initial_value=False)

last_ping_time = None
reassert_timer = None
alarm_timer = None
lock = threading.Lock()

def cancel_timers():
    global reassert_timer, alarm_timer
    for t in (reassert_timer, alarm_timer):
        if t and t.is_alive():
            t.cancel()

def reassert_high():
    out.on()
    print(f"[{datetime.now()}] Reassert: GPIO HIGH")

def check_no_ping():
    with lock:
        ts = last_ping_time
    if ts is not None:
        print(f"[{datetime.now()}] WARNING: No ping for 10 minutes since {ts}")

def on_ping(pkt):
    global last_ping_time, reassert_timer, alarm_timer
    if ICMP in pkt and pkt[ICMP].type == 8:
        if SOM_IP and pkt[IP].src != SOM_IP:
            return

        with lock:
            last_ping_time = datetime.now()

        out.on()
        print(f"[{last_ping_time}] Ping from {pkt[IP].src} -> GPIO HIGH")

        cancel_timers()
        reassert_timer = threading.Timer(REASSERT_SEC, reassert_high)
        reassert_timer.daemon = True
        reassert_timer.start()

        alarm_timer = threading.Timer(ALARM_SEC, check_no_ping)
        alarm_timer.daemon = True
        alarm_timer.start()

def cleanup(*_):
    cancel_timers()
    out.off()
    sys.exit(0)

def main():
    print("Sniffing ICMP echo requests...")
    bpf = "icmp and icmp[icmptype] = icmp-echo"
    if SOM_IP:
        bpf += f" and src host {SOM_IP}"
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    sniff(filter=bpf, prn=on_ping, store=False)

if __name__ == "__main__":
    main()
