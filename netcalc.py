"""ЛР5. Калькулятор подсетей и планировщик адресного пространства (VLSM).

Вариант 10: 10.5.5.0/24, Банк. зал 30, Кредитный отдел 25, Охрана 10,
Серверы 5, запас роста 30 %.
"""

import csv
import ipaddress
import sys

VARIANT = 10
VARIANT_BASE = "10.5.5.0/24"
VARIANT_DEPS = {"Банк. зал": 30, "Кредитный отдел": 25, "Охрана": 10, "Серверы": 5}
VARIANT_GROWTH = 30


# ---------------------------------------------------------------- Задание 1
def mask_to_binary(mask):
    """255.255.255.192 -> 11111111.11111111.11111111.11000000"""
    return ".".join(f"{int(octet):08b}" for octet in str(mask).split("."))


def address_type(ip):
    """Тип адреса. Порядок важен: 127.x и 169.254.x тоже is_private."""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "частный"
    return "публичный"


def subnet_info(cidr):
    iface = ipaddress.ip_interface(cidr)
    net = iface.network
    has_hosts = net.num_addresses > 2  # у /31 и /32 обычных узлов нет
    return {
        "Адрес узла": str(iface.ip),
        "Адрес сети": str(net.network_address),
        "Маска": str(net.netmask),
        "Префикс": f"/{net.prefixlen}",
        "Broadcast": str(net.broadcast_address),
        "Первый узел": str(net.network_address + 1) if has_hosts else "-",
        "Последний узел": str(net.broadcast_address - 1) if has_hosts else "-",
        "Количество узлов": net.num_addresses - 2 if has_hosts else 0,
        "Wildcard": str(net.hostmask),
        "Маска (двоичная)": mask_to_binary(net.netmask),
        "Тип адреса": address_type(iface.ip),
    }


# ---------------------------------------------------------------- Задание 2
def parse_cidr(text):
    """Принимает '10.0.0.5/26' и '10.0.0.5 255.255.255.192'
    (лишние пробелы допускаются). Возвращает IPv4Interface.
    При ошибке выбрасывает ValueError с понятным сообщением."""
    if text is None or not text.strip():
        raise ValueError("пустая строка")
    parts = text.replace("/", " / ").split()
    if "/" in parts:                      # формат адрес/маска
        if parts.count("/") != 1 or len(parts) != 3 or parts[1] != "/":
            raise ValueError(f"неверный формат: {text.strip()}")
        addr, mask = parts[0], parts[2]
    elif len(parts) == 2:                 # формат "адрес маска"
        addr, mask = parts
    elif len(parts) == 1:
        try:
            ipaddress.IPv4Address(parts[0])   # сначала проверим сам адрес
        except ValueError:
            raise ValueError(f"неверный IP-адрес: {parts[0]}") from None
        raise ValueError("не указана маска")
    else:
        raise ValueError(f"неверный формат: {text.strip()}")

    try:
        ipaddress.IPv4Address(addr)
    except ValueError:
        raise ValueError(f"неверный IP-адрес: {addr}") from None
    try:
        return ipaddress.IPv4Interface(f"{addr}/{mask}")
    except ValueError:
        msg = (f"недопустимая маска: {mask} (маска должна быть префиксом "
               "0-32 или непрерывной последовательностью единиц)")
        raise ValueError(msg) from None


def same_subnet(a, b):
    """a - адрес с маской, b - адрес без маски.
    True, если узел b находится в подсети узла a."""
    iface = parse_cidr(a)
    try:
        ip_b = ipaddress.IPv4Address(b.strip())
    except ValueError:
        raise ValueError(f"неверный IP-адрес второго узла: {b.strip()}") from None
    return ip_b in iface.network


# ---------------------------------------------------------------- VLSM
def with_growth(need, growth):
    """Число устройств с запасом роста growth % (округление вверх)."""
    return (need * (100 + growth) + 99) // 100


def prefix_for(hosts):
    """Минимальный префикс, которого хватит на hosts узлов."""
    prefix = 32
    while 2 ** (32 - prefix) - 2 < hosts:
        prefix -= 1
    return prefix


def vlsm(base_network, departments, growth=0):
    """departments: {название: число_устройств}. Возвращает список словарей."""
    base = ipaddress.ip_network(base_network, strict=False)
    plan = []
    current = base.network_address
    for name, need in sorted(departments.items(), key=lambda x: x[1], reverse=True):
        need_g = with_growth(need, growth)
        prefix = prefix_for(need_g)
        try:
            subnet = ipaddress.ip_network(f"{current}/{prefix}")
        except ValueError:
            msg = (f"Нельзя выделить /{prefix} для отдела «{name}» "
                   f"с адреса {current}: адрес не кратен размеру подсети")
            raise ValueError(msg) from None
        if not subnet.subnet_of(base):
            raise ValueError(f"Не хватает адресов для отдела «{name}»")
        plan.append({"name": name, "need": need, "need_g": need_g,
                     "subnet": subnet})
        current = subnet.broadcast_address + 1
    return plan


# ---------------------------------------------------------------- Задание 3
def plan_summary(base_network, plan):
    """Всего адресов, выделено, свободно, использование в %."""
    base = ipaddress.ip_network(base_network, strict=False)
    total = base.num_addresses
    allocated = sum(p["subnet"].num_addresses for p in plan)
    devices = sum(p["need"] for p in plan)
    usage = round(devices / allocated * 100, 1) if allocated else 0.0
    return {"Всего адресов": total,
            "Выделено": allocated,
            "Свободно": total - allocated,
            "Использование, %": usage}


def check_plan(base_network, plan):
    """Список ошибок: подсеть вне базовой сети, пересечение подсетей
    двух отделов. Пустой список - план корректен."""
    base = ipaddress.ip_network(base_network, strict=False)
    errors = []
    for p in plan:
        if not p["subnet"].subnet_of(base):
            errors.append(f"Подсеть {p['subnet']} отдела «{p['name']}» "
                          f"выходит за пределы {base}")
    for i in range(len(plan)):
        for j in range(i + 1, len(plan)):
            a, b = plan[i], plan[j]
            if a["subnet"].overlaps(b["subnet"]):
                errors.append(f"Подсети отделов «{a['name']}» ({a['subnet']}) "
                              f"и «{b['name']}» ({b['subnet']}) пересекаются")
    return errors


def min_base_prefix(base_network, departments, growth=0):
    """Если адресов не хватает, найти наименьшую сеть (самый длинный
    префикс), начинающуюся с того же адреса, в которую план помещается."""
    base = ipaddress.ip_network(base_network, strict=False)
    for prefix in range(base.prefixlen, -1, -1):
        net = ipaddress.ip_network(f"{base.network_address}/{prefix}",
                                   strict=False)
        try:
            vlsm(str(net), departments, growth)
            return net
        except ValueError:
            continue
    return None


def summarize(plan):
    """Возвращает (результат collapse_addresses, наименьшая общая надсеть)."""
    subnets = [p["subnet"] for p in plan]
    if not subnets:
        return [], None
    collapsed = list(ipaddress.collapse_addresses(subnets))
    sup = subnets[0]
    while not all(s.subnet_of(sup) for s in subnets):
        sup = sup.supernet()
    return collapsed, sup


def parse_departments(text):
    """'Продажи=60, Склад=25' -> {'Продажи': 60, 'Склад': 25}"""
    deps = {}
    for item in text.split(","):
        if not item.strip():
            continue
        if "=" not in item:
            raise ValueError(f"ожидается Название=число, получено: {item.strip()}")
        name, num = item.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError("пустое название отдела")
        try:
            n = int(num.strip())
        except ValueError:
            raise ValueError(f"число устройств должно быть целым: {num.strip()}") from None
        if n <= 0:
            raise ValueError(f"число устройств должно быть больше 0: {name}")
        if name in deps:
            raise ValueError(f"отдел «{name}» указан дважды")
        deps[name] = n
    if not deps:
        raise ValueError("не указан ни один отдел")
    return deps


def save_plan_csv(plan, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["department", "need", "need_with_growth", "subnet",
                    "gateway", "broadcast"])
        for p in plan:
            net = p["subnet"]
            w.writerow([p["name"], p["need"], p["need_g"], net,
                        net.network_address + 1, net.broadcast_address])


def print_plan(plan):
    print(f"\n{'Отдел':22}{'Нужно':>6}{'+запас':>8} "
          f"{'Подсеть':20}{'Диапазон':34}Broadcast")
    for p in plan:
        net = p["subnet"]
        rng = f"{net.network_address + 1} - {net.broadcast_address - 1}"
        print(f"{p['name']:22}{p['need']:>6}{p['need_g']:>8} "
              f"{str(net):20}{rng:34}{net.broadcast_address}")


def report_plan(base, deps, growth, csv_path=None):
    """Строит и печатает план. Возвращает 0, если всё в порядке, иначе 1.
    Используется пунктом 3 меню и подкомандой netkit vlsm."""
    try:
        plan = vlsm(base, deps, growth)
    except ValueError as e:
        print(f"\nОшибка: {e}")
        suggestion = min_base_prefix(base, deps, growth)
        if suggestion is None:
            print("Подходящую сеть найти не удалось.")
        else:
            print(f"Сеть {base} мала для этого плана. "
                  f"Предлагаемая сеть: {suggestion}")
        return 1

    print_plan(plan)
    print()
    for k, v in plan_summary(base, plan).items():
        print(f"{k:18}: {v}")
    errors = check_plan(base, plan)
    print("\nПроверка плана:", "ошибок нет" if not errors else "")
    for e in errors:
        print("  -", e)
    collapsed, sup = summarize(plan)
    print("Агрегация (collapse_addresses):", ", ".join(map(str, collapsed)))
    print("Наименьшая общая надсеть      :", sup)
    if csv_path:
        save_plan_csv(plan, csv_path)
        print(f"План сохранён в {csv_path}")
    return 1 if errors else 0


# ---------------------------------------------------------------- меню
def ask(prompt):
    value = input(prompt).strip()
    if not sys.stdin.isatty():      # ввод из файла/конвейера - показываем его
        print(value)
    return value


def menu_subnet_info():
    iface = parse_cidr(ask("Адрес (10.0.0.5/26 или 10.0.0.5 255.255.255.192): "))
    for k, v in subnet_info(str(iface)).items():
        print(f"{k:18}: {v}")


def menu_same_subnet():
    a = ask("Первый узел с маской: ")
    b = ask("Второй узел без маски: ")
    iface = parse_cidr(a)
    if same_subnet(a, b):
        print(f"Да, {b} находится в подсети {iface.network}")
    else:
        print(f"Нет, {b} не входит в подсеть {iface.network}")


def menu_vlsm():
    print(f"Enter - данные варианта {VARIANT}")
    base = ask(f"Базовая сеть [{VARIANT_BASE}]: ") or VARIANT_BASE
    ipaddress.ip_network(base, strict=False)          # проверка формата
    g = ask(f"Запас роста, % [{VARIANT_GROWTH}]: ")
    growth = int(g) if g else VARIANT_GROWTH
    if growth < 0:
        raise ValueError("запас роста не может быть отрицательным")
    default = ", ".join(f"{k}={v}" for k, v in VARIANT_DEPS.items())
    d = ask(f"Отделы [{default}]: ")
    deps = parse_departments(d) if d else dict(VARIANT_DEPS)
    report_plan(base, deps, growth, f"plan_v{VARIANT}.csv")


def main():
    actions = {"1": menu_subnet_info, "2": menu_same_subnet, "3": menu_vlsm}
    try:
        while True:
            print("\n==== Сетевой калькулятор ====")
            print("1 - Информация о подсети")
            print("2 - Находятся ли два узла в одной подсети")
            print("3 - План VLSM для своего варианта")
            print("0 - Выход")
            choice = ask("Ваш выбор: ")
            if choice == "0":
                print("Работа завершена")
                break
            action = actions.get(choice)
            if action is None:
                print("Нет такого пункта меню, введите 0-3")
                continue
            try:
                action()
            except ValueError as e:
                print("Ошибка:", e)
    except (KeyboardInterrupt, EOFError):
        print("\nРабота завершена")


if __name__ == "__main__":
    main()
