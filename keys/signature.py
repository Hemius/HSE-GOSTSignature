"""
signature.py — формирование и проверка ЭЦП ГОСТ Р 34.10-2012.

Реализует алгоритмы:
  - sign()   — алгоритм I
  - verify() — алгоритм II
  - вспомогательные функции сериализации подписи

Зависимости: math_utils, streebog, ec.
"""

import secrets

from math_utils import modinv
from hash.streebog import streebog
from ec.curve import Curve, Point, add, scalar_mul


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def _digest_size(curve: Curve) -> int:
    """Длина хэша в битах для данной кривой.

    По ГОСТ Р 34.10-2012:
      если 2^254 < q < 2^256  →  l = 256
      если 2^508 < q < 2^512  →  l = 512
    """
    return 256 if curve.q.bit_length() <= 256 else 512


def _hash_to_int(message: bytes, curve: Curve) -> int:
    """Вычисляет e = α mod q, где α — числовое представление хэша.

    Шаги 1–2 алгоритмов I и II:
      1. h = hash(M)          — вычислить хэш нужной длины
      2. α = int(h, big-end)  — интерпретировать как целое (MSB первым)
         e = α mod q
         если e = 0, то e := 1
    """
    h = streebog(message, _digest_size(curve))
    alpha = int.from_bytes(h, 'big')
    e = alpha % curve.q
    return e if e != 0 else 1


# ---------------------------------------------------------------------------
# Алгоритм I — формирование подписи
# ---------------------------------------------------------------------------

def sign(message: bytes, d: int, curve: Curve,
         _k_override: int | None = None) -> tuple[int, int]:
    """Формирует ЭЦП под сообщением message. Возвращает пару (r, s).

    Параметр _k_override фиксирует случайное k и нужен только для
    воспроизведения контрольных примеров А.1 и А.2.
    В обычном режиме k генерируется через secrets.randbelow.

    Алгоритм I:
      1. h = hash(M), e = int(h) mod q  (e := 1 если e = 0)
      2. k — случайное из (0, q)
      3. C = k*G, r = C.x mod q         (если r = 0, повторить с п.2)
      4. s = (r*d + k*e) mod q          (если s = 0, повторить с п.2)
      5. подпись ζ = (r, s)
    """
    if not (0 < d < curve.q):
        raise ValueError("Ключ подписи d должен удовлетворять 0 < d < q")
    if _k_override is not None and not (0 < _k_override < curve.q):
        raise ValueError("Параметр k должен удовлетворять 0 < k < q")

    e = _hash_to_int(message, curve)

    while True:
        k = _k_override if _k_override is not None \
            else secrets.randbelow(curve.q - 1) + 1

        C = scalar_mul(k, curve.G)
        r = C.x % curve.q
        if r == 0:
            if _k_override is not None:
                raise ValueError("Заданный k дает r = 0")
            continue

        s = (r * d + k * e) % curve.q
        if s == 0:
            if _k_override is not None:
                raise ValueError("Заданный k дает s = 0")
            continue

        return r, s


# ---------------------------------------------------------------------------
# Алгоритм II — проверка подписи
# ---------------------------------------------------------------------------

def verify(message: bytes, r: int, s: int,
           Q: Point, curve: Curve) -> bool:
    """Проверяет ЭЦП (r, s) под сообщением message. Возвращает True/False.

    Алгоритм II (шаги 1–7):
      1. Проверить 0 < r < q, 0 < s < q
      2. h = hash(M), e = int(h) mod q
      3. v = e^(-1) mod q
      4. z1 = s*v mod q,  z2 = -r*v mod q
      5. C = z1*G + z2*Q
      6. R = C.x mod q
      7. Подпись верна ⟺ R = r
    """
    # Шаг 1: границы r и s
    if not (0 < r < curve.q and 0 < s < curve.q):
        return False

    # Проверка публичного ключа Q без повторной проверки порядка.
    # Полная валидация (включая q·Q = O) должна быть выполнена вызывающим
    # кодом через validate_public_key() или неявно через load_public().
    if Q.curve is not curve:
        return False
    if Q.is_infinity():
        return False
    if not curve.contains(Q):
        return False

    # Шаги 2–3
    e = _hash_to_int(message, curve)
    v = modinv(e, curve.q)

    # Шаг 4
    z1 = s * v % curve.q
    z2 = (-r) * v % curve.q

    # Шаг 5
    C = add(scalar_mul(z1, curve.G), scalar_mul(z2, Q))
    if C.is_infinity():
        return False

    # Шаги 6–7
    return C.x % curve.q == r


# ---------------------------------------------------------------------------
# Сериализация подписи
# ---------------------------------------------------------------------------

def signature_to_bytes(r: int, s: int, curve: Curve) -> bytes:
    """Кодирует подпись (r, s) в байты.

    Формат: r || s, каждый компонент занимает L = ceil(q.bit_length/8) байт
    в big-endian. Итоговая длина: 64 байта для 256-битной кривой,
    128 байт для 512-битной.
    """
    L = (curve.q.bit_length() + 7) // 8
    return r.to_bytes(L, 'big') + s.to_bytes(L, 'big')


def signature_from_bytes(data: bytes, curve: Curve) -> tuple[int, int]:
    """Декодирует подпись из байтов, полученных signature_to_bytes().

    Raises:
        ValueError: если длина data не соответствует кривой.
    """
    L = (curve.q.bit_length() + 7) // 8
    if len(data) != 2 * L:
        raise ValueError(
            f"Неверная длина подписи: ожидалось {2*L} байт, получено {len(data)}"
        )
    r = int.from_bytes(data[:L], 'big')
    s = int.from_bytes(data[L:], 'big')
    return r, s
