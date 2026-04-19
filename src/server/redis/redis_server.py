import socket
import threading
import logging

REDIS_LOGGER = logging.getLogger("REDIS")
IOC_LOGGER = logging.getLogger("REDIS-IOC")

BUFFER_SIZE = 4096

RESP_PONG = b"+PONG\r\n"
RESP_OK = b"+OK\r\n"
RESP_ERROR_CMD = b"-ERR unknown command\r\n"
RESP_INFO = b"$5\r\nRedis\r\n"
RESP_NOAUTH = b"-NOAUTH Authentication required.\r\n"

ATTACK_COMMANDS = {
    "T1078_AUTH_ATTEMPT": ["AUTH"],
    "T1595_SCANNING": ["INFO", "KEYS", "CONFIG", "MONITOR"],
    "T1496_IMPACT": ["FLUSHALL", "SHUTDOWN", "SAVE"],
}

def parse_redis_command(data):
    try:
        decoded = data.decode("utf-8", errors="ignore").strip()

        if decoded.startswith("*"):
            parts = decoded.split("\r\n")
            cmd = parts[2].upper()
            args = []

            i = 4
            while i < len(parts):
                args.append(parts[i])
                i += 2

            return cmd, args

        raw = decoded.split(" ", 1)
        cmd = raw[0].upper()
        args = [raw[1]] if len(raw) > 1 else []

        return cmd, args

    except:
        return "UNKNOWN", []


def detect_redis_attack(command):
    matches = []
    for technique, cmds in ATTACK_COMMANDS.items():
        for pattern in cmds:
            if command.startswith(pattern):
                matches.append(technique)
                break
    return matches


def handle_client(client_socket, client_address, port):
    client_ip = client_address[0]
    REDIS_LOGGER.info(f"[CONNECT] {client_ip}:{client_address[1]} connected")

    try:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break

            command, args = parse_redis_command(data)
            iocs = detect_redis_attack(command)

            msg = f"[{client_ip}] CMD={command} ARGS={args}"

            if iocs:
                IOC_LOGGER.warning(f"[ATTACK] {msg} | MITRE={iocs}")
            else:
                REDIS_LOGGER.info(msg)

            # RESP protocol responses
            if command == "PING":
                client_socket.sendall(RESP_PONG)

            elif command == "AUTH":
                client_socket.sendall(RESP_OK)

            elif command == "INFO":
                client_socket.sendall(RESP_INFO)

            elif command == "ECHO":
                if args:
                    m = args[0].encode()
                    resp = f"${len(m)}\r\n".encode() + m + b"\r\n"
                    client_socket.sendall(resp)
                else:
                    client_socket.sendall(RESP_ERROR_CMD)

            elif command == "QUIT":
                client_socket.sendall(RESP_OK)
                break

            else:
                client_socket.sendall(RESP_ERROR_CMD)

    except Exception as e:
        REDIS_LOGGER.error(f"[ERROR] Client {client_ip}: {e}")

    finally:
        client_socket.close()
        REDIS_LOGGER.info(f"[DISCONNECT] {client_ip} closed")


def start_redis_honeypot(host="0.0.0.0", port=6379):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
        server.listen(10)
        REDIS_LOGGER.info(f"[START] Redis Honeypot running {host}:{port}")
    except Exception as e:
        REDIS_LOGGER.error(f"[BIND ERROR] {e}")
        return

    while True:
        try:
            sock, addr = server.accept()
            threading.Thread(
                target=handle_client,
                args=(sock, addr, port),
                daemon=True
            ).start()

        except KeyboardInterrupt:
            REDIS_LOGGER.info("[STOP] Redis Honeypot stopped")
            server.close()
            break

        except Exception as e:
            REDIS_LOGGER.error(f"[SERVER LOOP ERROR] {e}")
