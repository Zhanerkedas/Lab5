"""ЛР5. Параллельная проверка доступности сетевых сервисов."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor

PORT = 8100  # порт веб-сервера варианта 10: python -m http.server 8100

SERVICES = [
    ("Google HTTPS", "google.com", 443),
    ("GitHub SSH", "github.com", 22),
    ("Google DNS", "8.8.8.8", 53),
    ("Cloudflare DNS", "1.1.1.1", 53),
    ("Локальный веб-сервер", "127.0.0.1", PORT),
    ("Закрытый локальный порт", "127.0.0.1", PORT + 1),
    ("Несуществующий домен", "no-such-host.example", 80),
    ("Фильтруемый адрес", "10.255.255.1", 80),
    # свои сервисы
    ("Сайт Satbayev University", "satbayev.university", 443),
    ("Портал eGov", "egov.kz", 443),
    ("Почта Gmail IMAP", "imap.gmail.com", 993),
    ("Yandex DNS", "77.88.8.8", 53),
]


def get_services():
    """SERVICES + веб-интерфейс и DNS своего шлюза (шлюз определяется
    автоматически через netdiag)."""
    services = list(SERVICES)
    try:
        import netdiag
        gw = netdiag.get_default_gateway()
    except Exception:
        gw = None
    if gw:
        services.append(("Веб-интерфейс шлюза", gw, 80))
        services.append(("DNS своей сети (шлюз)", gw, 53))
    return services


def check_service(name, host, port, timeout=3):
    """Возвращает словарь: name, host, port, status, ms, addresses."""
    result = {"name": name, "host": host, "port": port,
              "status": "?", "ms": None, "addresses": []}
    # 1) DNS: все адреса узла
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        result["status"] = "DNS-ERROR"
        return result
    addrs = []
    for info in infos:
        a = info[4][0]
        if a not in addrs:
            addrs.append(a)
    result["addresses"] = addrs

    # 2) TCP-соединение с замером времени
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result["status"] = "OPEN"
    except ConnectionRefusedError:
        result["status"] = "REFUSED"
    except TimeoutError:              # socket.timeout - псевдоним TimeoutError
        result["status"] = "TIMEOUT"
    except OSError:
        result["status"] = "ERROR"
    result["ms"] = round((time.perf_counter() - start) * 1000, 1)
    return result


def check_all_sequential(services, timeout=3):
    return [check_service(*s, timeout=timeout) for s in services]


def check_all_parallel(services, workers=10, timeout=3):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda s: check_service(*s, timeout=timeout), services))


def print_table(results):
    print(f"{'Сервис':26}{'Узел':22}{'Порт':>6} {'Статус':10}{'мс':>8} Адресов")
    for r in results:
        ms = "" if r["ms"] is None else r["ms"]
        print(f"{r['name']:26}{r['host']:22}{r['port']:>6} {r['status']:10}"
              f"{ms:>8} {len(r['addresses'])}")


def run(parallel=False, workers=10, timeout=3):
    """Для netkit. Код завершения: 0 - все сервисы OPEN, 1 - есть недоступные."""
    services = get_services()
    t0 = time.perf_counter()
    if parallel:
        res = check_all_parallel(services, workers, timeout)
    else:
        res = check_all_sequential(services, timeout)
    elapsed = time.perf_counter() - t0
    print_table(res)
    mode = f"параллельно, workers={workers}" if parallel else "последовательно"
    print(f"\nВремя проверки ({mode}): {elapsed:.2f} с")
    return 0 if all(r["status"] == "OPEN" for r in res) else 1


if __name__ == "__main__":
    services = get_services()
    t0 = time.perf_counter()
    res = check_all_sequential(services)
    t1 = time.perf_counter()
    print_table(res)
    print(f"\nПоследовательно: {t1 - t0:.2f} с")

    print("\nСравнение времени:")
    print(f"{'Режим':20}Время, с")
    print(f"{'Последовательно':20}{t1 - t0:.2f}")
    for w in (1, 2, 5, 10, 20):
        t0 = time.perf_counter()
        check_all_parallel(services, workers=w)
        print(f"{'workers = ' + str(w):20}{time.perf_counter() - t0:.2f}")
