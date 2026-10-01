import socket
import time

def simulate_attack():
    print("=" * 50)
    print("   SIMULATING DoS UDP FLOOD ATTACK")
    print("=" * 50)
    print("Target: 8.8.8.8 on Port 80")
    
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Bind to a specific local port (44444) so live_detector.py 
    # groups all these packets into ONE massive network flow.
    sock.bind(("0.0.0.0", 44444)) 
    
    target_ip = "8.8.8.8"
    target_port = 80
    
    # Create a dummy payload
    payload = b"ATTACK_SIMULATION" * 20 
    
    print("Firing 5,000 packets rapidly... (This will take ~2 seconds)")
    try:
        for i in range(5000):
            sock.sendto(payload, (target_ip, target_port))
            # Tiny sleep to prevent local buffer overflow, but fast enough to look malicious
            time.sleep(0.0001) 
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print("\nAttack simulation complete! Check your live_detector.py terminal.")

if __name__ == "__main__":
    simulate_attack()