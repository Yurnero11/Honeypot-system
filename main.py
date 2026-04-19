import logging
import logging.handlers
import threading
import yaml
import sys
from pathlib import Path

from src.server.ssh.ssh_server import start_ssh_honeypot
from src.server.http.http_server import start_http_honeypot
from src.server.redis.redis_server import start_redis_honeypot


def setup_logging(log_level_str: str) -> None:
    log_dir = Path("logs/raw")
    log_dir.mkdir(parents=True, exist_ok=True)

    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    formatter = logging.Formatter(log_format)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)

    service_loggers = {
        "SSH": "ssh.log",
        "SSH-IOC": "ssh.log",
        "REDIS": "redis.log",
        "REDIS-IOC": "redis.log",
        "HTTP": "http.log",
        "HTTP-IOC": "http.log",
        "MAIN": "system.log",
    }

    for name, filename in service_loggers.items():
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / filename,
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)

        lg = logging.getLogger(name)
        lg.setLevel(log_level)
        lg.addHandler(file_handler)

        if name == "MAIN":
            lg.addHandler(console_handler)
        else:
            lg.propagate = False


def main() -> None:
    print("[+] Honeypot starting...")

    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print("[ERROR] config.yaml not found!")
        return

    setup_logging(config["logging"]["level"])
    main_logger = logging.getLogger("MAIN")

    server_cfg = config["server"]

    # SSH
    ssh_host = server_cfg.get("ssh_host", "0.0.0.0")
    ssh_port = server_cfg["ssh_port"]
    ssh_creds = config.get("credentials", {}).get("ssh", {})
    threading.Thread(
        target=start_ssh_honeypot,
        kwargs={
            "host": ssh_host,
            "port": ssh_port,
            "valid_user": ssh_creds.get("username", "admin"),
            "valid_pass": ssh_creds.get("password", "password"),
        },
        daemon=True,
        name="SSH-Honeypot",
    ).start()
    main_logger.info(f"[+] SSH honeypot launched on {ssh_host}:{ssh_port}")

    # HTTP
    http_host = server_cfg.get("http_host", "0.0.0.0")
    http_port = server_cfg["http_port"]
    threading.Thread(
        target=start_http_honeypot,
        kwargs={"host": http_host, "port": http_port},
        daemon=True,
        name="HTTP-Honeypot",
    ).start()
    main_logger.info(f"[+] HTTP honeypot launched on {http_host}:{http_port}")

    # Redis
    redis_host = server_cfg.get("redis_host", "0.0.0.0")
    redis_port = server_cfg["redis_port"]
    threading.Thread(
        target=start_redis_honeypot,
        kwargs={"host": redis_host, "port": redis_port},
        daemon=True,
        name="Redis-Honeypot",
    ).start()
    main_logger.info(f"[+] Redis honeypot launched on {redis_host}:{redis_port}")

    main_logger.info("[+] All honeypots running. Press Ctrl+C to stop.")

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        main_logger.info("[+] Stopping honeypot...")


if __name__ == "__main__":
    main()
