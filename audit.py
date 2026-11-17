"""ЛР5. Аудит IP-адресов устройств по плану адресации."""

import csv
import ipaddress
import sys


def load_plan(path):
    """plan.csv -> {отдел: IPv4Network}"""
    with open(path, encoding="utf-8-sig") as f:
        return {row["department"].strip(): ipaddress.ip_network(row["subnet"].strip())
                for row in csv.DictReader(f)}


def load_devices(path):
    """devices.csv: hostname,department,ip,gateway"""
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def audit(plan, devices):
    """Возвращает список кортежей (hostname, код, описание)."""
    problems = []
    seen_ips = {}
    for d in devices:
        host = (d.get("hostname") or "?").strip()
        dept = (d.get("department") or "").strip()
        raw_ip = (d.get("ip") or "").strip()
        raw_gw = (d.get("gateway") or "").strip()

        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            problems.append((host, "E1", f"неверный формат IP: {raw_ip}"))
            continue

        try:
            gw = ipaddress.ip_address(raw_gw)
        except ValueError:
            problems.append((host, "E1", f"неверный формат шлюза: {raw_gw}"))
            gw = None

        # E5 - дубликат проверяем до проверки отдела: адрес занят независимо от отдела
        if ip in seen_ips:
            problems.append((host, "E5", f"IP {ip} уже занят устройством "
                                         f"{seen_ips[ip]}"))
        else:
            seen_ips[ip] = host

        net = plan.get(dept)
        if net is None:
            problems.append((host, "E2", f"неизвестный отдел: {dept}"))
            continue

        if ip not in net:
            problems.append((host, "E3", f"{ip} не входит в подсеть отдела {net}"))
        elif ip == net.network_address:
            problems.append((host, "E4", f"{ip} - адрес сети {net}"))
        elif ip == net.broadcast_address:
            problems.append((host, "E4", f"{ip} - broadcast подсети {net}"))

        if gw is None:
            continue
        if gw == ip:
            problems.append((host, "E7", f"шлюз {gw} совпадает с IP устройства"))
        elif gw not in net:
            problems.append((host, "E6", f"шлюз {gw} вне подсети отдела {net}"))
        elif gw != net.network_address + 1:
            problems.append((host, "W1", f"шлюз {gw} не первый адрес подсети "
                                         f"(ожидается {net.network_address + 1})"))
    return problems


def save_report(problems, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["hostname", "code", "description"])
        w.writerows(problems)


def print_report(problems, devices):
    for host, code, text in problems:
        print(f"[{code}] {host:15} {text}")
    errors = sum(1 for _, c, _ in problems if c.startswith("E"))
    warnings = sum(1 for _, c, _ in problems if c.startswith("W"))
    with_remarks = {h for h, _, _ in problems}
    clean = sum(1 for d in devices
                if (d.get("hostname") or "?").strip() not in with_remarks)
    print(f"\nПроверено устройств: {len(devices)}, ошибок: {errors}, "
          f"предупреждений: {warnings}, без замечаний: {clean}")
    return errors


def run(plan_file, dev_file, report_file="audit_report.csv"):
    """Код завершения: 0 - ошибок нет, 1 - есть ошибки или файл не прочитан."""
    try:
        plan = load_plan(plan_file)
        devices = load_devices(dev_file)
    except (OSError, KeyError, ValueError) as e:
        print("Не удалось прочитать входные файлы:", e)
        return 1
    problems = audit(plan, devices)
    errors = print_report(problems, devices)
    save_report(problems, report_file)
    print(f"Замечания сохранены в {report_file}")
    return 1 if errors else 0


if __name__ == "__main__":
    plan_file = sys.argv[1] if len(sys.argv) > 1 else "plan_v10.csv"
    dev_file = sys.argv[2] if len(sys.argv) > 2 else "devices.csv"
    sys.exit(run(plan_file, dev_file))
