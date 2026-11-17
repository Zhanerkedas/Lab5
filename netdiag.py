"""ЛР5. Автоматическая пошаговая диагностика сети."""

import csv
import datetime
import os
import platform
import re
import socket
import subprocess
import time

SYSTEM = platform.system()  # "Windows", "Linux" или "Darwin" (macOS)
IS_WINDOWS = SYSTEM == "Windows"
LOG_FILE = "diag_log.csv"

# Для эксперимента «Ошибка DNS» замените DNS_HOST на несуществующий домен
DNS_HOST = os.environ.get("LAB5_DNS_HOST", "google.com")
WEB_HOST, WEB_PORT = "google.com", 443
EXTERNAL_IP = "8.8.8.8"

IPV4 = r"\d+\.\d+\.\d+\.\d+"


def run(cmd, timeout=15):
    """Запускает команду и возвращает (код возврата, вывод)."""
    try:
        enc = "cp866" if IS_WINDOWS else "utf-8"  # кодировка консоли Windows
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding=enc, errors="replace")
        return r.returncode, r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, ""


def parse_ping_times(out):
    """Все времена ответа из вывода ping: time=12.3 ms, время=12мс, time<1ms."""
    return [float(t) for t in re.findall(r"(?:time|время)[=<]\s*([\d.]+)", out)]


def ping(host, count=3):
    """Возвращает (успех, среднее время в мс или None).
    Успех - только если найдено хотя бы одно время ответа: на Windows ping
    возвращает код 0 и при ответе «Заданный узел недоступен»."""
    if not host:
        return False, None
    flag = "-n" if IS_WINDOWS else "-c"
    _, out = run(["ping", flag, str(count), host])
    times = parse_ping_times(out)
    if not times:
        return False, None
    return True, round(sum(times) / len(times), 1)


def parse_gateway(system, out):
    """Извлекает шлюз по умолчанию из вывода команды маршрутов."""
    if system == "Windows":
        # 0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.105  35  -> берём меньшую метрику
        routes = re.findall(rf"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+({IPV4})\s+{IPV4}\s+(\d+)",
                            out, re.MULTILINE)
        if not routes:
            return None
        return min(routes, key=lambda r: int(r[1]))[0]
    if system == "Darwin":
        m = re.search(rf"gateway:\s*({IPV4})", out)
    else:
        m = re.search(rf"default via ({IPV4})", out)
    return m.group(1) if m else None


def get_default_gateway():
    """Определяет шлюз по умолчанию. Возвращает строку с IP или None."""
    if SYSTEM == "Windows":
        cmd = ["route", "print", "-4", "0.0.0.0"]
    elif SYSTEM == "Darwin":
        cmd = ["route", "-n", "get", "default"]
    else:
        cmd = ["ip", "route"]
    _, out = run(cmd)
    return parse_gateway(SYSTEM, out)


def resolve(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def tcp_check(host, port, timeout=3):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.perf_counter() - start) * 1000, 1)
    except OSError:
        return False, None


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # пакеты не отправляются, выбирается маршрут
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def check_own_interface():
    """Если маршрута наружу нет, get_local_ip() вернёт 127.0.0.1 - это не
    «собственный интерфейс», поэтому шаг считается неуспешным."""
    ip = get_local_ip()
    if ip.startswith("127."):
        return False, None
    return ping(ip)


# Названия шагов (используются и в main, и в ADVICE)
S_STACK = "Стек TCP/IP (127.0.0.1)"
S_IFACE = "Собственный интерфейс"
S_GW = "Шлюз по умолчанию"
S_EXT = f"Внешняя сеть по IP ({EXTERNAL_IP})"
S_DNS = f"DNS ({DNS_HOST})"
S_WEB = f"Веб-сервис ({WEB_HOST}:{WEB_PORT})"

if IS_WINDOWS:
    ADVICE = {
        S_STACK: ["Сбросьте стек TCP/IP: netsh int ip reset (от администратора), "
                  "затем перезагрузите ПК"],
        S_IFACE: ["Проверьте, что адаптер включён и получил адрес: ipconfig /all",
                  "Запросите адрес у DHCP заново: ipconfig /release && ipconfig /renew",
                  "Проверьте кабель / подключение к Wi-Fi: netsh wlan show interfaces"],
        S_GW: ["Сверьте шлюз и маску: ipconfig (адрес шлюза должен быть в вашей подсети)",
               "Посмотрите таблицу маршрутов: route print -4",
               "Очистите ARP-кэш и повторите: arp -d * && ping <шлюз>"],
        S_EXT: ["Проверьте, на каком хопе обрывается путь: tracert -d 8.8.8.8",
                "Перезагрузите роутер / проверьте подключение провайдера",
                "Проверьте, не блокирует ли ICMP межсетевой экран: wf.msc"],
        S_DNS: ["Проверьте DNS-серверы: ipconfig /all, nslookup google.com",
                "Очистите кэш DNS: ipconfig /flushdns",
                "Попробуйте другой DNS: nslookup google.com 8.8.8.8"],
        S_WEB: ["Проверьте порт: Test-NetConnection google.com -Port 443 (PowerShell)",
                "Проверьте настройки прокси: netsh winhttp show proxy",
                "Проверьте брандмауэр/антивирус и системное время (ошибки TLS)"],
    }
else:
    ADVICE = {
        S_STACK: ["Проверьте интерфейс lo: ip addr show lo; при необходимости "
                  "sudo ip link set lo up"],
        S_IFACE: ["Проверьте адрес интерфейса: ip addr (macOS: ifconfig)",
                  "Перезапросите адрес DHCP: sudo dhclient -r && sudo dhclient "
                  "(macOS: sudo ipconfig set en0 DHCP)",
                  "Проверьте кабель / Wi-Fi: nmcli device status"],
        S_GW: ["Проверьте маршрут по умолчанию: ip route (macOS: netstat -rn)",
               "Проверьте ARP-запись шлюза: ip neigh (macOS: arp -a)",
               "Убедитесь, что шлюз в вашей подсети, перезагрузите роутер"],
        S_EXT: ["Найдите место обрыва: traceroute -n 8.8.8.8",
                "Проверьте подключение провайдера / роутер",
                "Проверьте правила межсетевого экрана: sudo iptables -L (macOS: pfctl -s rules)"],
        S_DNS: ["Проверьте DNS-серверы: cat /etc/resolv.conf или resolvectl status",
                "Проверьте разрешение имени напрямую: dig google.com @8.8.8.8",
                "Очистите кэш DNS: resolvectl flush-caches "
                "(macOS: sudo dscacheutil -flushcache)"],
        S_WEB: ["Проверьте порт: nc -vz google.com 443",
                "Проверьте HTTPS: curl -I https://google.com",
                "Проверьте прокси (переменные http_proxy/https_proxy) и системное время"],
    }


def log_result(step, ok, ms):
    """Дописывает строку в LOG_FILE: дата и время, имя компьютера,
    локальный IP, шаг, OK/FAIL, время в мс."""
    new_file = not os.path.exists(LOG_FILE)
    # BOM только при создании файла - тогда Excel правильно покажет кириллицу
    with open(LOG_FILE, "a", newline="", encoding="utf-8-sig" if new_file else "utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["datetime", "hostname", "local_ip", "step", "result", "ms"])
        w.writerow([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    socket.gethostname(), get_local_ip(), step,
                    "OK" if ok else "FAIL", "" if ms is None else ms])


def main(gateway=None):
    """Код завершения: 0 - все шаги OK, 1 - найден неуспешный шаг.
    Если gateway передан (netkit diag --gateway), он не определяется автоматически."""
    if gateway is None:
        gateway = get_default_gateway()
        # Эксперимент «Неверный шлюз»: раскомментируйте строку ниже
        # gateway = "192.168.250.1"
        if gateway is None:
            try:
                gateway = input("Шлюз не определён. Введите IP шлюза: ").strip()
            except EOFError:
                gateway = ""
    print(f"ОС: {SYSTEM}  Локальный IP: {get_local_ip()}  Шлюз: {gateway or '-'}\n")

    steps = [
        (S_STACK, lambda: ping("127.0.0.1")),
        (S_IFACE, check_own_interface),
        (S_GW, lambda: ping(gateway)),
        (S_EXT, lambda: ping(EXTERNAL_IP)),
        (S_DNS, lambda: (resolve(DNS_HOST) is not None, None)),
        (S_WEB, lambda: tcp_check(WEB_HOST, WEB_PORT)),
    ]
    for name, check in steps:
        ok, ms = check()
        log_result(name, ok, ms)
        extra = "" if ms is None else f"{ms} мс"
        print(f"[{'OK' if ok else 'FAIL'}] {name:32} {extra}")
        if not ok:
            print(f"\nДиагностика остановлена. Проблема на уровне: {name}")
            for tip in ADVICE.get(name, []):
                print("  -", tip)
            return 1
    print("\nВсе уровни работают.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
