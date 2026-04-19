import socket
import threading
import paramiko
import logging

from .fake_commands import fake_commands, DEFAULT_STATE, execute_command

SSH_LOGGER = logging.getLogger("SSH")
IOC_LOGGER = logging.getLogger("SSH-IOC")

HOST_KEY = paramiko.RSAKey.generate(2048)

SUSPICIOUS_PATTERNS = {
    "T1110_BRUTE": ["hydra", "medusa", "nmap --script ssh-brute"],
    "T1059_EXEC": ["bash -i", "sh -i", "python3 -c", "perl -e", "nc -e"],
    "T1105_TRANSFER": ["wget", "curl", "scp"],
    "T1068_PRIVESC": ["sudo", "chmod +x", "./exploit"],
    "T1083_DISCOVERY": ["cat /etc/shadow", "find / -type f", "ls -l /root"],
}


def detect_attack(cmd: str) -> list:
    detected = set()
    cmd_lower = cmd.lower()
    for technique, patterns in SUSPICIOUS_PATTERNS.items():
        for p in patterns:
            if p in cmd_lower:
                detected.add(technique)
    return list(detected)


class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, valid_user: str, valid_pass: str):
        self.event = threading.Event()
        self.username = None
        self.client_ip = client_ip
        self._valid_user = valid_user
        self._valid_pass = valid_pass

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        if username == self._valid_user and password == self._valid_pass:
            SSH_LOGGER.info(
                f"[AUTH SUCCESS] {self.client_ip} user={username}"
            )
            return paramiko.AUTH_SUCCESSFUL

        IOC_LOGGER.warning(
            f"[BRUTEFORCE] {self.client_ip} Failed Auth user={username!r} pass={password!r}"
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_pty_request(self, channel, term, w, h, pw, ph, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True


def start_shell(chan, username: str, client_ip: str) -> None:
    state = DEFAULT_STATE.copy()
    state["username"] = username
    current_line = ""
    input_buffer = ""

    def send_line(text: str = "") -> None:
        chan.send((text + "\r\n").encode())

    def redraw_prompt(current_cmd: str = "") -> None:
        prompt = f"{username}@{state.get('hostname', 'ubuntu')}:{state['cwd']}$ "
        chan.send(f"\r{prompt}{current_cmd}".encode())
        chan.send(b"\x1b[K")

    try:
        chan.send(f"Welcome to Ubuntu 22.04 LTS\r\n".encode())
        redraw_prompt()

        while True:
            data = chan.recv(1024)
            if not data:
                break

            input_buffer += data.decode("utf-8", errors="ignore")
            new_buffer = ""

            for char in input_buffer:
                if char in ("\r", "\n"):
                    cmd_line = current_line.strip()
                    current_line = ""
                    send_line()

                    if not cmd_line:
                        redraw_prompt()
                        continue

                    if cmd_line.lower() in ("exit", "quit"):
                        send_line("logout")
                        return

                    SSH_LOGGER.info(f"[CMD] {client_ip} {username}: {cmd_line}")
                    state["history"].append(cmd_line)

                    techs = detect_attack(cmd_line)
                    if techs:
                        IOC_LOGGER.warning(
                            f"[ATTACK] {client_ip} Detected MITRE: {techs} via command: {cmd_line}"
                        )

                    output = execute_command(state, cmd_line)
                    for line in str(output).splitlines():
                        send_line(line)

                    redraw_prompt()

                elif char in ("\x7f", "\x08"):
                    if current_line:
                        current_line = current_line[:-1]
                        redraw_prompt(current_line)

                elif "\x20" <= char <= "\x7e":
                    current_line += char
                    redraw_prompt(current_line)

                else:
                    new_buffer += char

            input_buffer = new_buffer

    except Exception as e:
        SSH_LOGGER.error(f"[SHELL ERROR] {client_ip}: {e}")
    finally:
        chan.close()
        SSH_LOGGER.info(f"[DISCONNECT] {client_ip} disconnected.")


def handle_ssh_client(client, addr, valid_user: str, valid_pass: str) -> None:
    client_ip = addr[0]
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)

    server = SSHServer(client_ip, valid_user, valid_pass)
    try:
        transport.start_server(server=server)
    except Exception as e:
        SSH_LOGGER.error(f"[TRANSPORT ERROR] {e}")
        return

    chan = transport.accept(20)
    if chan is None:
        SSH_LOGGER.error(f"[NO CHANNEL] {client_ip} No channel (auth failed or timeout).")
        return

    SSH_LOGGER.info(f"[CONNECT] {client_ip} connected, starting shell.")
    server.event.wait(10)

    if not server.event.is_set():
        SSH_LOGGER.error(f"[NO SHELL] {client_ip} No shell request.")
        return

    start_shell(chan, server.username or "unknown", client_ip)
    chan.close()


def start_ssh_honeypot(
        host: str = "0.0.0.0",
        port: int = 2222,
        valid_user: str = "admin",
        valid_pass: str = "password",
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((host, port))
    except Exception as e:
        SSH_LOGGER.error(f"[BIND ERROR] {e}")
        return

    sock.listen(100)
    SSH_LOGGER.info(f"[START] SSH Honeypot running on {host}:{port}")

    while True:
        try:
            client, addr = sock.accept()
            threading.Thread(
                target=handle_ssh_client,
                args=(client, addr, valid_user, valid_pass),
                name=f"SSH-{addr[0]}",
                daemon=True,
            ).start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            SSH_LOGGER.error(f"[LOOP ERROR] {e}")
