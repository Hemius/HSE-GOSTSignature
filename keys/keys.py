"""
keys.py — генерация, сохранение и загрузка ключевой пары.

Форматы файлов (JSON):
  Приватный ключ (.priv):
    { "version": 1, "paramset": "test-256", "d": "<hex>" }

  Публичный ключ (.pub):
    { "version": 1, "paramset": "test-256", "qx": "<hex>", "qy": "<hex>" }

При загрузке публичного ключа выполняется проверка:
  - координаты Q.x и Q.y находятся в диапазоне [0, p)
  - точка Q лежит на кривой
  - Q не является бесконечно удаленной точкой
  - q·Q = O (Q имеет правильный порядок)
"""

import json
import secrets
from pathlib import Path

from ec.curve import Curve, Point, scalar_mul
from ec.params import PARAMSETS


# ---------------------------------------------------------------------------
# Валидация публичного ключа
# ---------------------------------------------------------------------------

def validate_public_key(Q: Point, curve: Curve) -> None:
    """Проверяет корректность публичного ключа Q для кривой curve.

    Выполняет полную валидацию, включая ресурсоемкую проверку порядка q·Q = O.
    Следует вызывать один раз при загрузке ключа. После успешной валидации
    Q можно передавать в verify() без повторных проверок порядка.

    Raises:
        ValueError: при любой из неудач:
          - Q не привязан к данной кривой (Q.curve is not curve)
          - Q является бесконечно удаленной точкой
          - координаты Q.x и Q.y находятся вне диапазона [0, p)
          - Q не лежит на кривой
          - Q имеет порядок, отличный от q (q·Q ≠ O)
    """
    if Q.curve is not curve:
        raise ValueError("Публичный ключ привязан к другой кривой")
    if Q.is_infinity():
        raise ValueError("Публичный ключ является бесконечно удаленной точкой")
    if not (0 <= Q.x < curve.p and 0 <= Q.y < curve.p):
        raise ValueError("Координаты публичного ключа вне диапазона [0, p)")
    if not curve.contains(Q):
        raise ValueError("Публичный ключ не лежит на кривой")
    if not scalar_mul(curve.q, Q).is_infinity():
        raise ValueError("Публичный ключ имеет неверный порядок (q·Q ≠ O)")


# ---------------------------------------------------------------------------
# Генерация
# ---------------------------------------------------------------------------

def generate_keypair(curve: Curve) -> tuple[int, Point]:
    """Генерирует случайную ключевую пару (d, Q) для заданной кривой.

    d — случайное целое из диапазона 1 ≤ d ≤ q − 1, источник: secrets.randbelow.
    Q = d * G — ключ проверки подписи.

    Returns:
        (d, Q) — приватный ключ и соответствующий публичный ключ.
    """
    d = secrets.randbelow(curve.q - 1) + 1   # d ∈ [1, q-1]
    Q = scalar_mul(d, curve.G)
    return d, Q


# ---------------------------------------------------------------------------
# Сохранение
# ---------------------------------------------------------------------------

def save_private(path: Path, d: int, curve: Curve) -> None:
    """Сохраняет приватный ключ в JSON-файл.

    Args:
        path:  путь к файлу (обычно с расширением .priv).
        d:     ключ подписи.
        curve: параметры кривой (для определения набора параметров).
    """
    data = {
        'version':  1,
        'paramset': curve.name,
        'd':        format(d, 'x'),
    }
    path = Path(path)
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')


def save_public(path: Path, Q: Point, curve: Curve) -> None:
    """Сохраняет публичный ключ в JSON-файл.

    Args:
        path:  путь к файлу (обычно с расширением .pub).
        Q:     ключ проверки подписи.
        curve: параметры кривой.
    """
    if Q.is_infinity():
        raise ValueError("Нельзя сохранить бесконечно удаленную точку как ключ")
    data = {
        'version':  1,
        'paramset': curve.name,
        'qx':       format(Q.x, 'x'),
        'qy':       format(Q.y, 'x'),
    }
    path = Path(path)
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')


# ---------------------------------------------------------------------------
# Загрузка
# ---------------------------------------------------------------------------

def load_private(path: Path) -> tuple[int, Curve]:
    """Загружает приватный ключ из JSON-файла.

    Returns:
        (d, curve) — ключ подписи и параметры кривой.

    Raises:
        ValueError: если файл поврежден или параметры неизвестны.
    """
    data = json.loads(Path(path).read_text(encoding='utf-8'))

    _check_version(data)
    curve = _resolve_paramset(data)
    d = int(data['d'], 16)

    if not (0 < d < curve.q):
        raise ValueError(f"Значение d вне допустимого диапазона (0, q)")

    return d, curve


def load_public(path: Path) -> tuple[Point, Curve]:
    """Загружает публичный ключ из JSON-файла с проверкой корректности.

    Выполняет полную валидацию через validate_public_key():
      0. координаты x, y ∈ [0, p)
      1. Q не является точкой O
      2. Q лежит на кривой: y² ≡ x³ + ax + b (mod p)
      3. Q имеет порядок q: q·Q = O

    Returns:
        (Q, curve) — ключ проверки и параметры кривой.

    Raises:
        ValueError: если ключ поврежден или не прошел проверку.
    """
    data = json.loads(Path(path).read_text(encoding='utf-8'))

    _check_version(data)
    curve = _resolve_paramset(data)

    try:
        qx = int(data['qx'], 16)
        qy = int(data['qy'], 16)
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Неверный формат публичного ключа: {exc}") from exc

    Q = Point(qx, qy, curve)

    # Полная валидация (включая дорогую проверку q·Q = O)
    validate_public_key(Q, curve)

    return Q, curve


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def _check_version(data: dict) -> None:
    if data.get('version') != 1:
        raise ValueError(
            f"Неподдерживаемая версия формата ключа: {data.get('version')!r}"
        )


def _resolve_paramset(data: dict) -> Curve:
    name = data.get('paramset', '')
    if name not in PARAMSETS:
        raise ValueError(
            f"Неизвестный набор параметров: {name!r}. "
            f"Доступные: {list(PARAMSETS)}"
        )
    return PARAMSETS[name]
