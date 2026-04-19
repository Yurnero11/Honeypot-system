import os
import time
import threading
from datetime import datetime
import logging

# ----------------------------------------------------------------- GLOBALS ---
# Lock захищає fake_fs та fake_file_content від race condition
# коли кілька SSH-клієнтів одночасно пишуть/читають
_fs_lock = threading.Lock()

DEFAULT_STATE = {
    "cwd": "/home/admin",
    "history": [],
    "username": "admin",
    "hostname": "ubuntu",
    "uid": 1000,
    "gid": 1000,
}

SUSPICIOUS_PATTERNS = {
    "T1110_BRUTE": ["hydra", "medusa", "nmap --script ssh-brute"],
    "T1059_EXEC": ["bash -i", "sh -i", "python3 -c", "perl -e", "nc -e", "/bin/sh", "/bin/bash"],
    "T1105_TRANSFER": ["wget", "curl", "scp", "sftp"],
    "T1068_PRIVESC": ["sudo", "su root", "chmod +x", "./exploit", "id 0", "uid 0"],
    "T1083_DISCOVERY": ["cat /etc/shadow", "find / -type f", "ls -l /root", "cat /root"],
    "T1018_NETWORK_SCAN": ["nmap", "ping 192.168", "nc -z", "netcat -z", "masscan"],
    "T1049_NET_DISC": ["netstat -tulpn", "netstat -ano", "ss -tulpn", "ip addr", "ifconfig"],
    "T1567_EXFIL": ["cat /etc/shadow | curl", "cat /root/secret_key.txt | wget"],
}

fake_fs: dict = {
    "/": ["home", "var", "etc", "usr", "tmp", "root", "dev"],
    "/home": ["admin"],
    "/home/admin": ["file.txt", "notes.md", ".ssh"],
    "/home/admin/.ssh": ["id_rsa", "id_rsa.pub"],
    "/var": ["log", "www"],
    "/var/log": ["auth.log", "syslog", "apache2"],
    "/var/log/apache2": ["access.log"],
    "/var/www": ["html"],
    "/var/www/html": ["index.html", "config.php"],
    "/etc": ["passwd", "shadow", "hostname", "crontab"],
    "/usr": ["bin", "lib"],
    "/tmp": ["exploit.sh", "malware.bin"],
    "/root": ["secret_key.txt"],
    "/dev": ["null"],
}

fake_file_content: dict = {
    "/home/admin/file.txt": "Hello from the fake honeypot!\n",
    "/home/admin/notes.md": "# Notes\n- This is a fake file.\n",
    "/home/admin/.ssh/id_rsa": "FAKE PRIVATE KEY DATA\n",
    "/home/admin/.ssh/id_rsa.pub": "FAKE PUBLIC KEY DATA\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\n",
    "/etc/shadow": "root:*:19439:0:99999:7:::\nadmin:*:19439:0:99999:7:::\n",
    "/etc/hostname": "ubuntu-honeypot\n",
    "/etc/crontab": "0 5 * * * root /usr/bin/fake-backup\n",
    "/var/log/auth.log": f"{datetime.now().strftime('%b %d %H:%M:%S')} ubuntu sshd[1133]: Failed password for root\n",
    "/var/log/syslog": f"{datetime.now().strftime('%b %d %H:%M:%S')} ubuntu systemd[1]: Started Fake Service.\n",
    "/var/log/apache2/access.log": '1.2.3.4 - - [14/Nov/2025:12:00:00 +0200] "GET / HTTP/1.1" 200 45\n',
    "/var/www/html/index.html": "<!doctype html>Fake Web Page",
    "/var/www/html/config.php": "<?php $db_password='fakepass'; ?>",
    "/root/secret_key.txt": "TOP SECRET ROOT CREDENTIALS FAKE\n",
    "/tmp/exploit.sh": "#!/bin/bash\necho Exploit running...\n",
    "/tmp/malware.bin": "FAKE MALWARE BINARY CONTENT",
    "/dev/null": "",
}


def log_ioc(event: str) -> None:
    logging.info(f"[IOC-CMD] {event}")


def normalize_path(cwd: str, path: str) -> str:
    if not path or path == ".":
        return cwd
    if path.startswith("~"):
        path = "/home/admin" + path[1:]
    elif not path.startswith("/"):
        path = cwd + "/" + path

    parts = []
    for p in path.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if parts:
                parts.pop()
        else:
            parts.append(p)
    return "/" + "/".join(parts)


def is_directory(path: str) -> bool:
    with _fs_lock:
        return path in fake_fs


def list_dir_contents(path: str) -> list:
    with _fs_lock:
        return list(fake_fs.get(path, []))


def write_file(path: str, content: str = "", append: bool = False) -> None:
    if path == "/dev/null":
        return
    with _fs_lock:
        if path not in fake_file_content or not append:
            fake_file_content[path] = content
        else:
            fake_file_content[path] += content

        parent_path = "/".join(path.split("/")[:-1]) or "/"
        name = path.split("/")[-1]
        if parent_path in fake_fs and name not in fake_fs[parent_path]:
            fake_fs[parent_path].append(name)


def read_file(path: str) -> str | None:
    with _fs_lock:
        return fake_file_content.get(path)


def fake_ls(state: dict, args: list) -> str:
    show_all = any(a in ("-a", "-la", "-l") for a in args)
    show_long = any(a in ("-l", "-la") for a in args)

    target_paths = [normalize_path(state["cwd"], a) for a in args if not a.startswith("-")] or [state["cwd"]]

    full_output = []
    now_str = datetime.now().strftime("%b %d %H:%M")

    for path in target_paths:
        if not is_directory(path):
            content = read_file(path)
            if content is not None:
                full_output.append(path.split("/")[-1])
            else:
                full_output.append(f"ls: cannot access '{path.split('/')[-1]}': No such file or directory")
            continue

        files = list_dir_contents(path)
        if len(target_paths) > 1:
            full_output.append(f"\n{path}:")

        if show_long:
            output = []
            if show_all:
                output.append(f"drwxr-xr-x 2 {state['username']} {state['username']} 4096 {now_str} .")
                output.append(f"drwxr-xr-x 3 {state['username']} {state['username']} 4096 {now_str} ..")
            for f_name in files:
                full_f_path = normalize_path(path, f_name)
                if is_directory(full_f_path):
                    output.append(f"drwxr-xr-x 2 {state['username']} {state['username']} 4096 {now_str} {f_name}")
                else:
                    size = len(read_file(full_f_path) or "")
                    output.append(f"-rw-r--r-- 1 {state['username']} {state['username']} {size} {now_str} {f_name}")
            full_output.extend(output)
        else:
            display_files = ([".", ".."] + files) if show_all else [f for f in files if not f.startswith(".")]
            full_output.append("  ".join(display_files))

    return "\n".join(full_output)


def fake_pwd(state: dict, args: list) -> str:
    return state["cwd"]


def fake_cd(state: dict, args: list) -> str:
    if not args or args[0] == "~":
        state["cwd"] = "/home/admin"
        return ""
    path = normalize_path(state["cwd"], args[0])
    if is_directory(path):
        state["cwd"] = path
        return ""
    parent = "/".join(path.split("/")[:-1]) or "/"
    if path.split("/")[-1] in list_dir_contents(parent):
        return f"bash: cd: {args[0]}: Not a directory"
    return f"bash: cd: {args[0]}: No such file or directory"


def fake_whoami(state: dict, args: list) -> str:
    return state["username"]


def fake_id(state: dict, args: list) -> str:
    u = state["username"]
    uid, gid = state["uid"], state["gid"]
    return f"uid={uid}({u}) gid={gid}({u}) groups={gid}({u})"


def fake_uname(state: dict, args: list) -> str:
    return "Linux ubuntu 5.15 FakeKernel #1 SMP x86_64 GNU/Linux"


def fake_ps(state: dict, args: list) -> str:
    return (
        "  PID TTY          TIME CMD\n"
        " 1133 pts/0    00:00:00 sshd\n"
        " 1234 pts/0    00:00:00 bash\n"
        " 5678 pts/0    00:00:00 python3 honeypot.py\n"
    )


def fake_cat(state: dict, args: list) -> str:
    if not args:
        return "cat: missing operand"
    path = normalize_path(state["cwd"], args[0])
    content = read_file(path)
    if content is None:
        return f"cat: {args[0]}: No such file or directory"
    return content


def fake_echo(state: dict, args: list) -> str:
    return " ".join(args)


def fake_touch(state: dict, args: list) -> str:
    for f in args:
        path = normalize_path(state["cwd"], f)
        if path.split("/")[-1]:
            write_file(path, "")
    return ""


def fake_mkdir(state: dict, args: list) -> str:
    for d in args:
        path = normalize_path(state["cwd"], d)
        parent = "/".join(path.split("/")[:-1]) or "/"
        name = path.split("/")[-1]
        with _fs_lock:
            if path in fake_fs:
                return f"mkdir: cannot create directory '{d}': File exists"
            if parent not in fake_fs:
                return f"mkdir: cannot create directory '{d}': No such file or directory"
            fake_fs[path] = []
            if name not in fake_fs[parent]:
                fake_fs[parent].append(name)
    return ""


def fake_rm(state: dict, args: list) -> str:
    if not args:
        return "rm: missing operand"
    for f in args:
        path = normalize_path(state["cwd"], f)
        parent = "/".join(path.split("/")[:-1]) or "/"
        name = path.split("/")[-1]
        with _fs_lock:
            if path in fake_fs:
                if "-r" not in args:
                    return f"rm: cannot remove '{f}': Is a directory"
                del fake_fs[path]
            if path in fake_file_content:
                del fake_file_content[path]
            if parent in fake_fs and name in fake_fs[parent]:
                fake_fs[parent].remove(name)
            else:
                return f"rm: cannot remove '{f}': No such file or directory"
    return ""


def fake_sudo(state: dict, args: list) -> str:
    cmd_line = " ".join(args)
    log_ioc(f"SUDO attempt (PrivEsc): {cmd_line}")
    return f"[sudo] password for {state['username']}: Fake password accepted\n{cmd_line}: command executed as root (fake)"


def fake_su(state: dict, args: list) -> str:
    log_ioc("User switched to root via su")
    state.update({"username": "root", "cwd": "/root", "uid": 0, "gid": 0})
    return "Password: Fake password accepted\n"


def fake_ping(state: dict, args: list) -> str:
    target = args[0] if args else "127.0.0.1"
    time.sleep(0.3)
    return (
        f"PING {target} ({target}) 56(84) bytes of data.\n"
        f"64 bytes from {target}: icmp_seq=1 ttl=64 time=0.045 ms\n"
        f"64 bytes from {target}: icmp_seq=2 ttl=64 time=0.038 ms\n"
        f"--- {target} ping statistics ---\n"
        "2 packets transmitted, 2 received, 0% packet loss, time 1001ms"
    )


def fake_curl(state: dict, args: list) -> str:
    url = args[0] if args else "http://example.com"
    log_ioc(f"curl attempt to {url}")
    return f"<!doctype html>\n<html><body>Fake curl response from {url}</body></html>"


def fake_wget(state: dict, args: list) -> str:
    url = args[0] if args else "http://example.com/file.txt"
    log_ioc(f"wget file download: {url}")
    filename = url.split("/")[-1]
    path = normalize_path(state["cwd"], filename)
    write_file(path, f"Fake downloaded content from {url}")
    return (
        f"Saving to: '{filename}'\n"
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} URL: {url} [12345/12345] -> \"{filename}\" [1]"
    )


def fake_net_cmd(state: dict, args: list) -> str:
    cmd_name = args[0] if args else ""
    log_ioc(f"Network discovery command: {' '.join(args)}")

    if cmd_name in ("ip", "ifconfig"):
        return (
            "1: lo: <LOOPBACK,UP> mtu 65536\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n"
            "    inet 192.168.1.55/24 brd 192.168.1.255\n"
        )
    if cmd_name == "netstat":
        return (
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1133/sshd\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      2000/apache\n"
        )
    if cmd_name in ("nc", "netcat"):
        return "Connection refused"
    if cmd_name == "ssh":
        return f"ssh: connect to host {args[1]} port 22: Connection refused" if len(args) > 1 else "ssh: usage error"
    return f"{cmd_name}: command not found"


fake_commands: dict = {
    "ls": fake_ls,
    "pwd": fake_pwd,
    "cd": fake_cd,
    "whoami": fake_whoami,
    "id": fake_id,
    "uname": fake_uname,
    "ps": fake_ps,
    "cat": fake_cat,
    "echo": fake_echo,
    "touch": fake_touch,
    "mkdir": fake_mkdir,
    "rm": fake_rm,
    "rmdir": fake_rm,
    "sudo": fake_sudo,
    "su": fake_su,
    "ping": fake_ping,
    "curl": fake_curl,
    "wget": fake_wget,
    "ifconfig": lambda s, a: fake_net_cmd(s, ["ifconfig"] + a),
    "ip": lambda s, a: fake_net_cmd(s, ["ip"] + a),
    "netstat": lambda s, a: fake_net_cmd(s, ["netstat"] + a),
    "nc": lambda s, a: fake_net_cmd(s, ["nc"] + a),
    "netcat": lambda s, a: fake_net_cmd(s, ["netcat"] + a),
    "ssh": lambda s, a: fake_net_cmd(s, ["ssh"] + a),
    "scp": lambda s, a: fake_net_cmd(s, ["scp"] + a),
    "history": lambda s, a: "\n".join(f"{i + 1} {cmd}" for i, cmd in enumerate(s["history"])),
    "which": lambda s, a: f"/usr/bin/{a[0]}" if a and a[
        0] in fake_commands else f"which: no {a[0] if a else '?'} in ({os.getenv('PATH', '/usr/bin:/bin')})",
}


def execute_command(state: dict, cmd_line: str) -> str:
    redirect_type = None
    redirect_target = None

    if ">>" in cmd_line:
        parts = cmd_line.split(">>", 1)
        redirect_type = ">>"
    elif ">" in cmd_line:
        parts = cmd_line.split(">", 1)
        redirect_type = ">"
    else:
        parts = [cmd_line]

    pipeline_line = parts[0].strip()

    if redirect_type:
        if len(parts) > 1 and parts[1].strip():
            redirect_target = normalize_path(state["cwd"], parts[1].strip().split()[0])
        else:
            return f"bash: syntax error near unexpected token '{redirect_type}'"

    cmds = [c.strip() for c in pipeline_line.split("|")]
    output = ""

    for c in cmds:
        tokens = c.split()
        if not tokens:
            continue

        name, args = tokens[0], tokens[1:]
        if name in fake_commands:
            try:
                output = str(fake_commands[name](state, args))
            except Exception as e:
                output = f"{name}: error: {e}"
                break
        else:
            output = f"bash: {name}: command not found"
            break

    if redirect_type and redirect_target:
        if output.startswith("bash:") and "command not found" in output:
            return output
        if is_directory(redirect_target):
            return f"bash: {redirect_target.split('/')[-1]}: Is a directory"
        write_file(redirect_target, output + "\n", append=(redirect_type == ">>"))
        return ""

    return output
