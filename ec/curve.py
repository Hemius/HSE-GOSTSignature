"""
curve.py — операции на эллиптической кривой ГОСТ Р 34.10-2012.

Реализует:
  - Curve: параметры кривой y² ≡ x³ + ax + b (mod p)
  - Point: точка кривой, включая бесконечно удаленную O
  - сложение точек
  - скалярное умножение k·P методом двоичного разложения (double-and-add)
"""

from math_utils import modinv


# ---------------------------------------------------------------------------
# Кривая
# ---------------------------------------------------------------------------

class Curve:
    """Эллиптическая кривая y² ≡ x³ + ax + b (mod p) над конечным полем F_p.

    Атрибуты:
        p  — простой модуль поля
        a  — коэффициент кривой
        b  — коэффициент кривой
        q  — порядок базовой точки G (простое число)
        G  — базовая (генераторная) точка порядка q
    """

    __slots__ = ('p', 'a', 'b', 'q', 'G', 'name')

    def __init__(self, p: int, a: int, b: int, q: int,
                 gx: int, gy: int, name: str = '', validate: bool = True):
        self.p    = p
        self.a    = a
        self.b    = b
        self.q    = q
        self.name = name
        self.G    = Point(gx, gy, self)

        if validate:
            self.validate()

    def validate(self) -> None:
        """Проверяет базовые инварианты параметров кривой.

        Проверка включает:
        - принадлежность базовой точки G данной кривой;
        - выполнение условия q·G = O.

        Это ресурсоемкая операция, так как включает скалярное умножение q·G.
        Для стандартных именованных наборов ее можно отложить через
        validate=False и вызвать явно при необходимости.

        Важно: метод не выполняет полную криптографическую экспертизу параметров
        и не проверяет простоту p/q или полный порядок группы.

        Raises:
            ValueError: если G не лежит на кривой или q·G ≠ O.
        """
        if not self.contains(self.G):
            raise ValueError(
                f"Базовая точка G не лежит на кривой {self.name!r}"
            )
        if not scalar_mul(self.q, self.G).is_infinity():
            raise ValueError(
                f"q·G ≠ O для кривой {self.name!r}: порядок точки не совпадает с q"
            )

    def contains(self, P: 'Point') -> bool:
        """Проверяет, лежит ли точка P на кривой.

        Для бесконечно удаленной точки всегда True.
        Для остальных: y² ≡ x³ + ax + b (mod p).
        """
        if P.is_infinity():
            return True
        lhs = (P.y * P.y) % self.p
        rhs = (pow(P.x, 3, self.p) + self.a * P.x + self.b) % self.p
        return lhs == rhs

    def __repr__(self) -> str:
        return f'Curve({self.name!r})' if self.name else f'Curve(p={self.p:#x})'


# ---------------------------------------------------------------------------
# Точка
# ---------------------------------------------------------------------------

class Point:
    """Точка эллиптической кривой.

    Бесконечно удаленная точка O хранится как Point(None, None, curve).
    Для обычных точек ожидается, что x и y — целые числа из [0, p-1].

    Конструктор не проверяет принадлежность точки кривой.
    Для этого используется Curve.contains().
    """

    __slots__ = ('x', 'y', 'curve')

    def __init__(self, x, y, curve: Curve):
        self.x     = x
        self.y     = y
        self.curve = curve

    def is_infinity(self) -> bool:
        """True если это бесконечно удаленная точка O."""
        return self.x is None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        if self.curve is not other.curve:
            return False
        return self.x == other.x and self.y == other.y

    def __neg__(self) -> 'Point':
        """Противоположная точка: -(x, y) = (x, -y mod p)."""
        if self.is_infinity():
            return self
        return Point(self.x, (-self.y) % self.curve.p, self.curve)

    def __repr__(self) -> str:
        if self.is_infinity():
            return 'Point(O)'
        return f'Point({self.x:#x}, {self.y:#x})'


# ---------------------------------------------------------------------------
# Сложение точек
# ---------------------------------------------------------------------------

def add(P: Point, Q: Point) -> Point:
    """Сложение двух точек эллиптической кривой.

    Обрабатываются стандартные случаи группового закона:
      1. P = O → Q
      2. Q = O → P
      3. x1 = x2, y1 = -y2 (mod p) → O   (P + (-P) = O)
      4. P = Q (удвоение): λ = (3x1² + a) / (2y1)
      5. P ≠ Q: λ = (y2 - y1) / (x2 - x1)
      
    Координаты результата:
      x3 = λ² - x1 - x2 (mod p)
      y3 = λ(x1 - x3) - y1 (mod p)
    """
    # Точки должны лежать на одной кривой
    if P.curve is not Q.curve:
        raise ValueError("Точки принадлежат разным кривым")

    # Случаи 1–2: нейтральный элемент
    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P

    curve = P.curve
    p = curve.p

    if P.x == Q.x:
        # Случай 3: P + (-P) = O
        if (P.y + Q.y) % p == 0:
            return Point(None, None, curve)
        # Случай 4: P = Q — удвоение
        # λ = (3x1² + a) * (2y1)^(-1) mod p
        lam = (3 * P.x * P.x + curve.a) * modinv(2 * P.y, p) % p
    else:
        # Случай 5: P ≠ Q — сложение
        # λ = (y2 - y1) * (x2 - x1)^(-1) mod p
        lam = (Q.y - P.y) * modinv((Q.x - P.x) % p, p) % p

    x3 = (lam * lam - P.x - Q.x) % p
    y3 = (lam * (P.x - x3) - P.y) % p
    return Point(x3, y3, curve)


# ---------------------------------------------------------------------------
# Скалярное умножение
# ---------------------------------------------------------------------------

def scalar_mul(k: int, P: Point) -> Point:
    """Вычисляет k·P методом двоичного разложения (double-and-add).

    Разбирает k побитово от LSB к MSB:
      - на каждом шаге удваиваем текущее слагаемое addend;
      - если бит равен 1 — прибавляем addend к результату.

    Сложность: O(log k) операций сложения точек.

    Обрабатывает k = 0 (→ O) и k < 0 (→ k·(-P)).
    """
    if k == 0 or P.is_infinity():
        return Point(None, None, P.curve)

    if k < 0:
        return scalar_mul(-k, -P)

    result = Point(None, None, P.curve)   # O — нейтральный элемент
    addend = P

    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)      # удвоение
        k >>= 1

    return result
