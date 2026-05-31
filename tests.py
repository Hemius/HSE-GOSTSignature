"""
tests.py — тесты корректности реализации
Контрольные примеры из стандартов:
  - хэши M1 и M2 из Приложения А ГОСТ Р 34.11-2012;
  - примеры А.1 и А.2 формирования подписи из Приложения А ГОСТ Р 34.10-2012.

Проверка реализации:
  - mod_pow и тест Миллера — Рабина;
  - корректность встроенных наборов параметров;
  - validate_public_key;
  - сериализация и десериализация подписи;
  - граничные случаи sign/verify;
  - полный цикл генерация → подпись → проверка.
"""

from hash.streebog import streebog
from ec.curve import Point, scalar_mul, add
from ec.params import GOST256_TEST, GOST512_TEST, PARAMSETS
from keys.keys import generate_keypair
from keys.signature import sign, verify, signature_to_bytes
from math_utils import mod_pow, is_probably_prime


# ---------------------------------------------------------------------------
# Вспомогательная функция
# ---------------------------------------------------------------------------

def _assert(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)


def _raises(fn, msg: str) -> None:
    """Проверяет, что fn() вызывает ValueError."""
    try:
        fn()
        raise AssertionError(msg)
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# 1. math_utils
# ---------------------------------------------------------------------------

def test_math_utils() -> None:
    """mod_pow совпадает со встроенным pow; Миллер — Рабин распознает простые и составные"""
    cases = [(2, 10, 1000, 24), (7, 100, 13, pow(7, 100, 13)),
             (5, 1024, 17, pow(5, 1024, 17))]
    for a, k, n, expected in cases:
        _assert(mod_pow(a, k, n) == expected,
                f'mod_pow({a},{k},{n}) = {mod_pow(a,k,n)}, ожидалось {expected}')

    _assert(is_probably_prime(2),      'is_probably_prime(2) должно быть True')
    _assert(is_probably_prime(7919),   'is_probably_prime(7919) должно быть True')
    _assert(not is_probably_prime(1),  'is_probably_prime(1) должно быть False')
    _assert(not is_probably_prime(100),'is_probably_prime(100) должно быть False')
    # Числа Кармайкла — проходят тест Ферма, но Миллер — Рабин их отсекает
    _assert(not is_probably_prime(561),  '561 — число Кармайкла, должно быть False')
    _assert(not is_probably_prime(1105), '1105 — число Кармайкла, должно быть False')
    _assert(not is_probably_prime(1729), '1729 — число Кармайкла, должно быть False')


# ---------------------------------------------------------------------------
# 2. Стрибог
# ---------------------------------------------------------------------------

def test_streebog() -> None:
    """Контрольные хэши M1 и M2 из Приложения А ГОСТ Р 34.11-2012"""
    M1 = bytes.fromhex('32313039383736353433' * 6 + '323130')
    M2 = bytes.fromhex(
        'fbe2e5f0eee3c820'
        'fbeafaebef20fffbf0e1e0f0f520e0ed'
        '20e8ece0ebe5f0f2f120fff0eeec20f1'
        '20faf2fee5e2202ce8f6f3ede220e8e6'
        'eee1e8f0f2d1202ce8f0f2e5e220e5d1'
    )

    cases = [
        (M1, 512,
         '486f64c1917879417fef082b3381a4e2'
         '11c324f074654c38823a7b76f830ad00'
         'fa1fbae42b1285c0352f227524bc9ab1'
         '6254288dd6863dccd5b9f54a1ad0541b'),
        (M1, 256,
         '00557be5e584fd52a449b16b0251d05d'
         '27f94ab76cbaa6da890b59d8ef1e159d'),
        (M2, 512,
         '28fbc9bada033b1460642bdcddb90c3f'
         'b3e56c497ccd0f62b8a2ad4935e85f03'
         '7613966de4ee00531ae60f3b5a47f8da'
         'e06915d5f2f194996fcabf2622e6881e'),
        (M2, 256,
         '508f7e553c06501d749a66fc28c6cac0'
         'b005746d97537fa85d9e40904efed29d'),
    ]
    for msg, bits, expected in cases:
        got = streebog(msg, bits).hex()
        _assert(got == expected,
                f'H_{bits}(M{1 if msg is M1 else 2}): '
                f'получено {got}, ожидалось {expected}')


# ---------------------------------------------------------------------------
# 3. Параметры кривых
# ---------------------------------------------------------------------------

def test_curve_params() -> None:
    """Проверяет корректность встроенных констант параметров кривых
    Все параметры заданы в коде и должны соответствовать математическим
    условиям эллиптической кривой над конечным простым полем
    """
    for name, curve in PARAMSETS.items():
        _assert(curve.name == name,
                f'{name}: curve.name = {curve.name!r}, ожидалось {name!r}')

        _assert(curve.p > 3,
                f'{name}: p должно быть больше 3')
        _assert(is_probably_prime(curve.p, t=10),
                f'{name}: p не является (вероятно) простым')
        _assert(is_probably_prime(curve.q, t=10),
                f'{name}: q не является (вероятно) простым')

        _assert(0 <= curve.a < curve.p,
                f'{name}: коэффициент a вне диапазона [0, p)')
        _assert(0 <= curve.b < curve.p,
                f'{name}: коэффициент b вне диапазона [0, p)')

        _assert(not curve.G.is_infinity(),
                f'{name}: базовая точка G не должна быть точкой O')
        _assert(0 <= curve.G.x < curve.p,
                f'{name}: координата G.x вне диапазона [0, p)')
        _assert(0 <= curve.G.y < curve.p,
                f'{name}: координата G.y вне диапазона [0, p)')

        discriminant = (
            4 * pow(curve.a, 3, curve.p)
            + 27 * pow(curve.b, 2, curve.p)
        ) % curve.p
        _assert(discriminant != 0,
                f'{name}: дискриминант равен 0, кривая вырождена')

        _assert(curve.contains(curve.G),
                f'{name}: базовая точка G не лежит на кривой')
        _assert(scalar_mul(curve.q, curve.G).is_infinity(),
                f'{name}: q·G ≠ O')


# ---------------------------------------------------------------------------
# 4. Контрольный пример подписи (Приложение А.1 ГОСТ Р 34.10-2012)
# ---------------------------------------------------------------------------

def test_signature_known() -> None:
    """Проверка математики на контрольном примере А.1 (256-бит) из стандарта"""
    c = GOST256_TEST
    d     = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
    k     = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3
    e     = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
    r_exp = 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493
    s_exp = 0x1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40
    Qx    = 0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B
    Qy    = 0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA

    C = scalar_mul(k, c.G)
    r = C.x % c.q
    _assert(r == r_exp, f'r = {r:#x}, ожидалось {r_exp:#x}')

    s = (r * d + k * e) % c.q
    _assert(s == s_exp, f's = {s:#x}, ожидалось {s_exp:#x}')

    Q = Point(Qx, Qy, c)
    from math_utils import modinv
    v  = modinv(e, c.q)
    z1 = s * v % c.q
    z2 = (-r) * v % c.q
    C_v = add(scalar_mul(z1, c.G), scalar_mul(z2, Q))
    _assert(C_v.x % c.q == r_exp,
            f'verify R = {C_v.x % c.q:#x}, ожидалось {r_exp:#x}')


# ---------------------------------------------------------------------------
# 4б. Контрольный пример подписи А.2 (Приложение А.2 ГОСТ Р 34.10-2012)
# ---------------------------------------------------------------------------

def test_signature_known_512() -> None:
    """Проверка математики на контрольном примере А.2 (512-бит) из стандарта"""
    c = GOST512_TEST
    d     = 0xBA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4
    k     = 0x359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1
    e     = 0x3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C
    r_exp = 0x2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36
    s_exp = 0x1081B394696FFE8E6585E7A9362D26B6325F56778AADBC081C0BFBE933D52FF5823CE288E8C4F362526080DF7F70CE406A6EEB1F56919CB92A9853BDE73E5B4A
    Qx    = 0x115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1
    Qy    = 0x37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61EA199441D943FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC

    C = scalar_mul(k, c.G)
    r = C.x % c.q
    _assert(r == r_exp, f'r (А.2) = {r:#x}, ожидалось {r_exp:#x}')

    s = (r * d + k * e) % c.q
    _assert(s == s_exp, f's (А.2) = {s:#x}, ожидалось {s_exp:#x}')

    Q = Point(Qx, Qy, c)
    from math_utils import modinv
    v  = modinv(e, c.q)
    z1 = s * v % c.q
    z2 = (-r) * v % c.q
    C_v = add(scalar_mul(z1, c.G), scalar_mul(z2, Q))
    _assert(C_v.x % c.q == r_exp,
            f'verify R (А.2) = {C_v.x % c.q:#x}, ожидалось {r_exp:#x}')


# ---------------------------------------------------------------------------
# 3б. validate_public_key
# ---------------------------------------------------------------------------

def test_validate_public_key() -> None:
    """Проверяет обработку корректного и некорректных публичных ключей."""
    from keys.keys import validate_public_key
    curve = GOST256_TEST
    d, Q = generate_keypair(curve)

    # Корректный ключ не вызывает исключение
    validate_public_key(Q, curve)

    # Q с другой кривой
    Q_wrong = Point(Q.x, Q.y, GOST512_TEST)
    try:
        validate_public_key(Q_wrong, curve)
        raise AssertionError("Ожидался ValueError: чужая кривая")
    except ValueError:
        pass

    # Q = O
    Q_inf = Point(None, None, curve)
    try:
        validate_public_key(Q_inf, curve)
        raise AssertionError("Ожидался ValueError: точка O")
    except ValueError:
        pass

    # Q не на кривой
    Q_bad = Point(1, 1, curve)
    try:
        validate_public_key(Q_bad, curve)
        raise AssertionError("Ожидался ValueError: не на кривой")
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# 6. Полный цикл работы подписи
# ---------------------------------------------------------------------------

def test_end_to_end() -> None:
    """Полный цикл: генерация → подпись → проверка на всех встроенных наборах параметров"""
    msg     = b'GOST R 34.10-2012 end-to-end test'
    msg_bad = b'GOST R 34.10-2012 end-to-end test!'

    for name, curve in PARAMSETS.items():
        d, Q = generate_keypair(curve)

        r, s = sign(msg, d, curve)
        _assert(verify(msg, r, s, Q, curve),
                f'{name}: подпись не прошла проверку')
        _assert(not verify(msg_bad, r, s, Q, curve),
                f'{name}: измененное сообщение прошло проверку')
        _assert(not verify(msg, (r + 1) % curve.q, s, Q, curve),
                f'{name}: подпись с r+1 прошла проверку')
        _assert(not verify(msg, r, (s + 1) % curve.q, Q, curve),
                f'{name}: подпись с s+1 прошла проверку')


# ---------------------------------------------------------------------------
# 8. Граничные случаи и негативные сценарии
# ---------------------------------------------------------------------------

def test_edge_cases() -> None:
    """Граничные случаи: чужой ключ, границы r/s, длина подписи, d, пустые сообщения"""
    from keys.signature import signature_to_bytes, signature_from_bytes

    curve = GOST256_TEST
    d, Q = generate_keypair(curve)
    msg = b'edge case test'
    r, s = sign(msg, d, curve)

    # --- Чужой публичный ключ ---
    d2, Q2 = generate_keypair(curve)
    _assert(not verify(msg, r, s, Q2, curve),
            'Подпись не должна проходить с чужим публичным ключом')

    # --- Границы r и s из §6.2 ГОСТа: допустимо только 0 < r,s < q ---
    _assert(not verify(msg, 0, s, Q, curve),
            'r=0 должно быть отвергнуто')
    _assert(not verify(msg, r, 0, Q, curve),
            's=0 должно быть отвергнуто')
    _assert(not verify(msg, curve.q, s, Q, curve),
            'r=q должно быть отвергнуто')
    _assert(not verify(msg, r, curve.q, Q, curve),
            's=q должно быть отвергнуто')

    # --- Неверная длина файла подписи ---
    sig_bytes = signature_to_bytes(r, s, curve)
    _raises(lambda: signature_from_bytes(sig_bytes[:-1], curve),
            'Усеченный файл подписи должен дать ValueError')
    _raises(lambda: signature_from_bytes(sig_bytes + b'\x00', curve),
            'Файл подписи с лишним байтом должен дать ValueError')
    _raises(lambda: signature_from_bytes(b'', curve),
            'Пустой файл подписи должен дать ValueError')

    # --- Проверка d в sign() ---
    _raises(lambda: sign(msg, 0, curve),
            'sign(d=0) должен дать ValueError')
    _raises(lambda: sign(msg, curve.q, curve),
            'sign(d=q) должен дать ValueError')
    _raises(lambda: sign(msg, -1, curve),
            'sign(d=-1) должен дать ValueError')

    # --- Пустое сообщение ---
    r_e, s_e = sign(b'', d, curve)
    _assert(verify(b'', r_e, s_e, Q, curve),
            'Пустое сообщение: подпись должна проверяться')
    _assert(not verify(b'\x00', r_e, s_e, Q, curve),
            'Сообщение \\x00 не должно проходить проверку как пустое сообщение')

    # --- Граничные длины сообщений (63, 64, 65 байт) ---
    for length in (63, 64, 65):
        m = bytes(range(256)) [:length]  # детерминированный контент
        r_l, s_l = sign(m, d, curve)
        _assert(verify(m, r_l, s_l, Q, curve),
                f'Сообщение {length} байт: подпись не прошла проверку')
        _assert(not verify(m + b'\xff', r_l, s_l, Q, curve),
                f'Сообщение {length} байт: измененное не должно проходить')


# ---------------------------------------------------------------------------
# 9. Длина сериализованной подписи
# ---------------------------------------------------------------------------

def test_signature_lengths() -> None:
    """Сериализованная подпись: 64 байта для 256 бит, 128 байт для 512 бит"""
    message = b'test message for signature length'

    d256, _ = generate_keypair(GOST256_TEST)
    r256, s256 = sign(message, d256, GOST256_TEST)
    sig256 = signature_to_bytes(r256, s256, GOST256_TEST)
    _assert(len(sig256) == 64, '256-битная подпись должна быть 64 байта')

    d512, _ = generate_keypair(GOST512_TEST)
    r512, s512 = sign(message, d512, GOST512_TEST)
    sig512 = signature_to_bytes(r512, s512, GOST512_TEST)
    _assert(len(sig512) == 128, '512-битная подпись должна быть 128 байт')


# ---------------------------------------------------------------------------
# Запуск всех тестов
# ---------------------------------------------------------------------------

_TESTS = [
    ('math_utils',                              test_math_utils),
    ('streebog',                                test_streebog),
    ('curve_params',                            test_curve_params),
    ('validate_public_key',                     test_validate_public_key),
    ('signature_known_256',                     test_signature_known),
    ('signature_known_512',                     test_signature_known_512),
    ('signature_lengths',                       test_signature_lengths),
    ('edge_cases',                              test_edge_cases),
    ('end_to_end',                              test_end_to_end),
]


def run_all() -> None:
    """Запускает все тесты, печатает результаты"""
    print('Запуск встроенных тестов...')
    print()

    passed = failed = 0
    for name, fn in _TESTS:
        try:
            fn()
            print(f'  ok   {name}')
            passed += 1
        except AssertionError as exc:
            print(f'  FAIL {name}: {exc}')
            failed += 1
        except Exception as exc:
            print(f'  FAIL {name}: неожиданная ошибка — {exc}')
            failed += 1

    print()
    print(f'Итого: {passed} прошли, {failed} провалились')

    if failed:
        raise SystemExit(1)
    else:
        print('Все тесты прошли успешно')
