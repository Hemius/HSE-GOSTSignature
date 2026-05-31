"""
cli.py — интерфейс командной строки.

Подкоманды:
  keygen  — сгенерировать ключевую пару
  sign    — подписать файл
  verify  — проверить подпись
  test    — запустить встроенные тесты

Использование:
  python gost_signature.py keygen --paramset test-256 --out keys/mykey
  python gost_signature.py sign   --in doc.txt --key keys/mykey.priv --out doc.sig
  python gost_signature.py verify --in doc.txt --key keys/mykey.pub  --sig doc.sig
  python gost_signature.py test
"""

import argparse
import sys
from pathlib import Path

from keys.keys import generate_keypair, save_private, save_public, load_private, load_public
from keys.signature import sign, verify, signature_to_bytes, signature_from_bytes
from ec.params import PARAMSETS


# ---------------------------------------------------------------------------
# Команда: keygen
# ---------------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> None:
    curve = PARAMSETS[args.paramset]

    print(f'Генерация ключевой пары ({args.paramset})...')
    d, Q = generate_keypair(curve)

    priv_path = Path(args.out).with_suffix('.priv')
    pub_path  = Path(args.out).with_suffix('.pub')

    priv_path.parent.mkdir(parents=True, exist_ok=True)

    save_private(priv_path, d, curve)
    save_public(pub_path, Q, curve)

    print(f'  Приватный ключ: {priv_path}')
    print(f'  Публичный ключ: {pub_path}')


# ---------------------------------------------------------------------------
# Команда: sign
# ---------------------------------------------------------------------------

def cmd_sign(args: argparse.Namespace) -> None:
    in_path  = Path(args.infile)
    key_path = Path(args.key)
    out_path = Path(args.out)

    if not in_path.exists():
        _die(f'Файл не найден: {in_path}')
    if not key_path.exists():
        _die(f'Файл ключа не найден: {key_path}')

    message = in_path.read_bytes()
    d, curve = load_private(key_path)

    print(f'Подписываю {in_path} ...')
    r, s = sign(message, d, curve)

    sig_bytes = signature_to_bytes(r, s, curve)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(sig_bytes)

    print(f'  Подпись сохранена: {out_path}  ({len(sig_bytes)} байт)')
    print(f'  r = {r:#x}')
    print(f'  s = {s:#x}')


# ---------------------------------------------------------------------------
# Команда: verify
# ---------------------------------------------------------------------------

def cmd_verify(args: argparse.Namespace) -> bool:
    in_path  = Path(args.infile)
    key_path = Path(args.key)
    sig_path = Path(args.sig)

    for p in (in_path, key_path, sig_path):
        if not p.exists():
            _die(f'Файл не найден: {p}')

    message   = in_path.read_bytes()
    Q, curve  = load_public(key_path)
    sig_bytes = sig_path.read_bytes()

    try:
        r, s = signature_from_bytes(sig_bytes, curve)
    except ValueError as exc:
        print(f'Ошибка формата подписи: {exc}', file=sys.stderr)
        return False

    print(f'Проверяю подпись для {in_path} ...')
    ok = verify(message, r, s, Q, curve)

    if ok:
        print('  Подпись ВЕРНА.')
    else:
        print('  Подпись НЕВЕРНА.', file=sys.stderr)

    return ok


# ---------------------------------------------------------------------------
# Команда: test
# ---------------------------------------------------------------------------

def cmd_test(_args: argparse.Namespace | None = None) -> None:
    import tests
    tests.run_all()


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def _die(msg: str) -> None:
    print(f'Ошибка: {msg}', file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

# Таблица доступных наборов параметров — выводится в --help верхнего уровня
# и в `keygen --help`.
_PARAMSET_HELP = """\
Доступные наборы параметров (--paramset):

  Тестовые (только для проверки реализации — из Приложения А ГОСТ Р 34.10-2012):
    test-256       256-битная тестовая кривая (Пример 1, Приложение А.1)
    test-512       512-битная тестовая кривая (Пример 2, Приложение А.2)

  Стандартные 256-битные TC26:
    tc26-256-A     id-tc26-gost-3410-2012-256-paramSetA
                   RFC 7836, Appendix A.2; Weierstrass-представление
    tc26-256-B     id-tc26-gost-3410-2012-256-paramSetB
                   OID: RFC 9215; параметры: RFC 4357 / CryptoPro-A
    tc26-256-C     id-tc26-gost-3410-2012-256-paramSetC
                   OID: RFC 9215; параметры: RFC 4357 / CryptoPro-B
    tc26-256-D     id-tc26-gost-3410-2012-256-paramSetD
                   OID: RFC 9215; параметры: RFC 4357 / CryptoPro-C

  Стандартные 256-битные CryptoPro (RFC 4357):
    cryptopro-A    id-GostR3410-2001-CryptoPro-A-ParamSet
    cryptopro-B    id-GostR3410-2001-CryptoPro-B-ParamSet
    cryptopro-C    id-GostR3410-2001-CryptoPro-C-ParamSet

  Стандартные 512-битные TC26 (RFC 7836):
    tc26-512-A     id-tc26-gost-3410-12-512-paramSetA
                   Appendix A.1; Weierstrass
    tc26-512-B     id-tc26-gost-3410-12-512-paramSetB
                   Appendix A.1; Weierstrass
    tc26-512-C     id-tc26-gost-3410-2012-512-paramSetC
                   Appendix A.2; Weierstrass-представление
"""


def main() -> None:
    main_epilog = (
        'Примеры:\n'
        '  python gost_signature.py keygen --paramset tc26-256-B --out keys/mykey\n'
        '  python gost_signature.py sign   --in doc.txt --key keys/mykey.priv --out doc.sig\n'
        '  python gost_signature.py verify --in doc.txt --key keys/mykey.pub  --sig doc.sig\n'
        '  python gost_signature.py test\n'
        '\n'
        'Подробнее по каждой команде:\n'
        '  python gost_signature.py <команда> --help\n'
        '\n'
        + _PARAMSET_HELP
    )

    parser = argparse.ArgumentParser(
        prog='gost_signature',
        description='ЭЦП ГОСТ Р 34.10-2012 с хэш-функцией ГОСТ Р 34.11-2012 («Стрибог»).',
        epilog=main_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='cmd', required=True,
                                metavar='{keygen,sign,verify,test}')

    # keygen
    p = sub.add_parser(
        'keygen',
        help='Сгенерировать ключевую пару',
        description=(
            'Сгенерировать ключевую пару для выбранного набора параметров.\n'
            'Создает два JSON-файла: <PREFIX>.priv (приватный ключ) и\n'
            '<PREFIX>.pub (публичный ключ). Промежуточные директории\n'
            'создаются автоматически.'
        ),
        epilog=(
            'Пример:\n'
            '  python gost_signature.py keygen --paramset tc26-256-B --out keys/mykey\n'
            '\n'
            + _PARAMSET_HELP
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('--paramset', required=True,
                   choices=list(PARAMSETS),
                   metavar='NAME',
                   help='Имя набора параметров кривой (полный список — см. ниже)')
    p.add_argument('--out', required=True,
                   metavar='PREFIX',
                   help='Префикс выходных файлов (добавятся .priv и .pub)')

    # sign
    p = sub.add_parser(
        'sign',
        help='Подписать файл',
        description=(
            'Подписать произвольный файл приватным ключом.\n'
            'Длина файла подписи: 64 байта для 256-битной кривой,\n'
            '128 байт — для 512-битной. Набор параметров берется из ключа.'
        ),
        epilog=(
            'Пример:\n'
            '  python gost_signature.py sign --in doc.txt --key keys/mykey.priv --out doc.sig'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('--in', dest='infile', required=True,
                   metavar='FILE', help='Подписываемый файл')
    p.add_argument('--key', required=True,
                   metavar='FILE.priv', help='Файл приватного ключа')
    p.add_argument('--out', required=True,
                   metavar='FILE.sig', help='Выходной файл подписи')

    # verify
    p = sub.add_parser(
        'verify',
        help='Проверить подпись',
        description=(
            'Проверить подпись файла публичным ключом.\n'
            'Код возврата: 0 — подпись верна, 1 — подпись неверна\n'
            'или формат файла подписи некорректен.'
        ),
        epilog=(
            'Пример:\n'
            '  python gost_signature.py verify --in doc.txt --key keys/mykey.pub --sig doc.sig'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('--in', dest='infile', required=True,
                   metavar='FILE', help='Проверяемый файл')
    p.add_argument('--key', required=True,
                   metavar='FILE.pub', help='Файл публичного ключа')
    p.add_argument('--sig', required=True,
                   metavar='FILE.sig', help='Файл подписи')

    # test
    sub.add_parser(
        'test',
        help='Запустить встроенные тесты',
        description=(
            'Запустить встроенные тесты корректности: контрольные примеры M1/M2\n'
            'для Стрибога (256 и 512 бит), А.1/А.2 для формирования подписи,\n'
            'проверку всех наборов параметров, граничные случаи sign/verify\n'
            'и полный цикл генерация → подпись → проверка.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    args = parser.parse_args()

    if args.cmd == 'keygen':
        cmd_keygen(args)
    elif args.cmd == 'sign':
        cmd_sign(args)
    elif args.cmd == 'verify':
        sys.exit(0 if cmd_verify(args) else 1)
    elif args.cmd == 'test':
        cmd_test(args)


if __name__ == '__main__':
    main()
