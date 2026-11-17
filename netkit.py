"""ЛР5. Единая утилита командной строки.

Примеры:
  python netkit.py calc 10.0.0.5/26
  python netkit.py vlsm 10.5.5.0/24 "Банк. зал=30" "Кредитный отдел=25" "Охрана=10" "Серверы=5" --growth 30 --csv plan_v10.csv
  python netkit.py audit plan_v10.csv devices.csv --report audit_report.csv
  python netkit.py diag
  python netkit.py services --parallel
"""

import argparse

import netcalc


def cmd_calc(args):
    try:
        iface = netcalc.parse_cidr(args.address)
    except ValueError as e:
        print("Ошибка:", e)
        return 1
    for k, v in netcalc.subnet_info(str(iface)).items():
        print(f"{k:18}: {v}")
    return 0


def cmd_vlsm(args):
    try:
        netcalc.ipaddress.ip_network(args.base, strict=False)
        deps = netcalc.parse_departments(",".join(args.departments))
        if args.growth < 0:
            raise ValueError("запас роста не может быть отрицательным")
    except ValueError as e:
        print("Ошибка:", e)
        return 1
    return netcalc.report_plan(args.base, deps, args.growth, args.csv)


def cmd_audit(args):
    import audit
    return audit.run(args.plan, args.devices, args.report)


def cmd_diag(args):
    import netdiag
    return netdiag.main(gateway=args.gateway)


def cmd_services(args):
    import services
    return services.run(parallel=args.parallel, workers=args.workers,
                        timeout=args.timeout)


def positive_int(text):
    n = int(text)
    if n < 1:
        raise argparse.ArgumentTypeError("значение должно быть >= 1")
    return n


def main(argv=None):
    parser = argparse.ArgumentParser(description="Сетевые утилиты ЛР5 (вариант 10)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("calc", help="калькулятор подсети")
    p.add_argument("address", help="10.0.0.5/26 или '10.0.0.5 255.255.255.192'")
    p.set_defaults(func=cmd_calc)

    p = sub.add_parser("vlsm", help="план адресации VLSM с запасом роста")
    p.add_argument("base", help="базовая сеть, например 10.5.5.0/24")
    p.add_argument("departments", nargs="+",
                   help='отделы: "Банк. зал=30" "Охрана=10" (или через запятую)')
    p.add_argument("--growth", type=int, default=0, help="запас роста, %% (по умолчанию 0)")
    p.add_argument("--csv", metavar="FILE", help="сохранить план в CSV")
    p.set_defaults(func=cmd_vlsm)

    p = sub.add_parser("audit", help="аудит IP-адресов устройств по плану")
    p.add_argument("plan", help="CSV с планом (plan_v10.csv)")
    p.add_argument("devices", help="CSV с устройствами (devices.csv)")
    p.add_argument("--report", metavar="FILE", default="audit_report.csv",
                   help="файл отчёта (по умолчанию audit_report.csv)")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("diag", help="пошаговая диагностика подключения")
    p.add_argument("--gateway", metavar="IP",
                   help="IP шлюза (если не указан - определяется автоматически)")
    p.set_defaults(func=cmd_diag)

    p = sub.add_parser("services", help="проверка доступности сервисов")
    p.add_argument("--parallel", action="store_true", help="параллельная проверка")
    p.add_argument("--workers", type=positive_int, default=10,
                   help="число потоков (по умолчанию 10)")
    p.add_argument("--timeout", type=float, default=3, help="таймаут, с (по умолчанию 3)")
    p.set_defaults(func=cmd_services)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nРабота завершена")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
