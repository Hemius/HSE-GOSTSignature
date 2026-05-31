"""
params.py — параметры эллиптических кривых ГОСТ Р 34.10-2012.

В реализации используются параметры короткой формы Вейерштрасса:
  p  — характеристика конечного поля F_p
  a  — коэффициент кривой
  b  — коэффициент кривой
  q  — порядок циклической подгруппы
  gx — x-координата базовой точки G
  gy — y-координата базовой точки G

Тестовые наборы из Приложения А стандарта:
  GOST256_TEST — 256-битная кривая (Приложение А.1, Пример 1)
  GOST512_TEST — 512-битная кривая (Приложение А.2, Пример 2)

Стандартные именованные наборы параметров (Weierstrass):
  256-битные:
    TC26_256_A   — id-tc26-gost-3410-2012-256-paramSetA
                   RFC 7836, Appendix A.2 (twisted-Edwards-форма
                   с эквивалентным Weierstrass-представлением)
    TC26_256_B   — id-tc26-gost-3410-2012-256-paramSetB
                   OID определен в RFC 9215
                   значения параметров — из RFC 4357
                   (CryptoPro-A-ParamSet)
    TC26_256_C   — id-tc26-gost-3410-2012-256-paramSetC
                   OID определен в RFC 9215
                   значения параметров — из RFC 4357
                   (CryptoPro-B-ParamSet)
    TC26_256_D   — id-tc26-gost-3410-2012-256-paramSetD
                   OID определен в RFC 9215
                   значения параметров — из RFC 4357
                   (CryptoPro-C-ParamSet)
    CRYPTOPRO_A  — id-GostR3410-2001-CryptoPro-A-ParamSet (RFC 4357)
    CRYPTOPRO_B  — id-GostR3410-2001-CryptoPro-B-ParamSet (RFC 4357)
    CRYPTOPRO_C  — id-GostR3410-2001-CryptoPro-C-ParamSet (RFC 4357)
  512-битные:
    TC26_512_A   — id-tc26-gost-3410-12-512-paramSetA
                   RFC 7836, Appendix A.1 (Weierstrass)
    TC26_512_B   — id-tc26-gost-3410-12-512-paramSetB
                   RFC 7836, Appendix A.1 (Weierstrass)
    TC26_512_C   — id-tc26-gost-3410-2012-512-paramSetC
                   RFC 7836, Appendix A.2 (twisted-Edwards-форма
                   с эквивалентным Weierstrass-представлением)

Примечание:
  Наборы TC26_256_B/C/D математически совпадают с CryptoPro-A/B/C,
  но представлены отдельными объектами Curve.
  Это сделано для того, чтобы при сохранении ключей
  фиксировалось выбранное пользователем имя набора параметров.
"""

from ec.curve import Curve

# ---------------------------------------------------------------------------
# 256-битная тестовая кривая
# Источник: ГОСТ Р 34.10-2012, Приложение А.1 (Пример 1)
# ---------------------------------------------------------------------------

GOST256_TEST = Curve(
    name = 'test-256',
    p  = 0x8000000000000000000000000000000000000000000000000000000000000431,
    a  = 7,
    b  = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E,
    q  = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3,
    gx = 2,
    gy = 0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8,
    validate = True,
)

# ---------------------------------------------------------------------------
# 512-битная тестовая кривая
# Источник: ГОСТ Р 34.10-2012, Приложение А.2 (Пример 2)
# ---------------------------------------------------------------------------

GOST512_TEST = Curve(
    name = 'test-512',
    p  = 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373,
    a  = 7,
    b  = 0x1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC,
    q  = 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF,
    gx = 0x24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A,
    gy = 0x2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E,
    validate = True,
)

# ---------------------------------------------------------------------------
# Стандартные 256-битные наборы параметров — TC26
#
# Из четырех публичных OID-ов (paramSetA..D) непосредственно в RFC 7836
# определен только paramSetA — в Appendix A.2 (twisted-Edwards-форма с
# эквивалентным Weierstrass-представлением).
#
# Для paramSetB/C/D RFC 7836 ссылается на RFC 4357:
# «In case of elliptic curves with 256-bit prime moduli,
# the parameters defined in RFC4357 are proposed for use». 
# Сами OID-ы для этих наборов зафиксированы
# в методических рекомендациях ТК 26 и в RFC 9215,
# а значения параметров берутся из RFC 4357 (CryptoPro-A/B/C).
# ---------------------------------------------------------------------------

# id-tc26-gost-3410-2012-256-paramSetA
# Источник значений: RFC 7836, Appendix A.2 (twisted-Edwards-форма;
# здесь используются эквивалентные Weierstrass-параметры a, b, x, y).
TC26_256_A = Curve(
    name = 'tc26-256-A',
    p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97,
    a  = 0xC2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335,
    b  = 0x295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513,
    q  = 0x400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67,
    gx = 0x91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28,
    gy = 0x32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C,
    validate = False,
)

# id-tc26-gost-3410-2012-256-paramSetB
# OID: RFC 9215
# Значения параметров: RFC 4357 (id-GostR3410-2001-CryptoPro-A-ParamSet).
TC26_256_B = Curve(
    name = 'tc26-256-B',
    p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97,
    a  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94,
    b  = 0xa6,
    q  = 0xffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893,
    gx = 0x01,
    gy = 0x8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14,
    validate = False,
)

# id-tc26-gost-3410-2012-256-paramSetC
# OID: RFC 9215
# Значения параметров: RFC 4357 (id-GostR3410-2001-CryptoPro-B-ParamSet).
TC26_256_C = Curve(
    name = 'tc26-256-C',
    p  = 0x8000000000000000000000000000000000000000000000000000000000000c99,
    a  = 0x8000000000000000000000000000000000000000000000000000000000000c96,
    b  = 0x3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b,
    q  = 0x800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f,
    gx = 0x01,
    gy = 0x3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc,
    validate = False,
)

# id-tc26-gost-3410-2012-256-paramSetD
# OID: RFC 9215
# Значения параметров: RFC 4357 (id-GostR3410-2001-CryptoPro-C-ParamSet).
TC26_256_D = Curve(
    name = 'tc26-256-D',
    p  = 0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b,
    a  = 0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598,
    b  = 0x805a,
    q  = 0x9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9,
    gx = 0x00,
    gy = 0x41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67,
    validate = False,
)

# ---------------------------------------------------------------------------
# Стандартные 256-битные наборы параметров — CryptoPro
#
# OID-ы и значения определены в RFC 4357 для ГОСТ Р 34.10-2001.
# В ГОСТ Р 34.10-2012 для 256-битного варианта эти параметры
# переиспользуются без изменений (RFC 7836).
# ---------------------------------------------------------------------------

# id-GostR3410-2001-CryptoPro-A-ParamSet
# Источник: RFC 4357
CRYPTOPRO_A = Curve(
    name = 'cryptopro-A',
    p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97,
    a  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94,  # p - 3
    b  = 0xa6,
    q  = 0xffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893,
    gx = 0x01,
    gy = 0x8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14,
    validate = False,
)

# id-GostR3410-2001-CryptoPro-B-ParamSet
# Источник: RFC 4357
CRYPTOPRO_B = Curve(
    name = 'cryptopro-B',
    p  = 0x8000000000000000000000000000000000000000000000000000000000000c99,
    a  = 0x8000000000000000000000000000000000000000000000000000000000000c96,  # p - 3
    b  = 0x3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b,
    q  = 0x800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f,
    gx = 0x01,
    gy = 0x3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc,
    validate = False,
)

# id-GostR3410-2001-CryptoPro-C-ParamSet
# Источник: RFC 4357
CRYPTOPRO_C = Curve(
    name = 'cryptopro-C',
    p  = 0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b,
    a  = 0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598,  # p - 3
    b  = 0x805a,
    q  = 0x9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9,
    gx = 0x00,
    gy = 0x41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67,
    validate = False,
)

# ---------------------------------------------------------------------------
# Стандартные 512-битные наборы параметров — RFC 7836 (TC26)
# ---------------------------------------------------------------------------

# id-tc26-gost-3410-12-512-paramSetA
# Источник: RFC 7836, Appendix A.1 (каноническая форма Weierstrass)
TC26_512_A = Curve(
    name = 'tc26-512-A',
    p  = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7,
    a  = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4,  # p - 3
    b  = 0x00E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760,
    q  = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275,
    gx = 0x03,
    gy = 0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4,
    validate = False,
)

# id-tc26-gost-3410-12-512-paramSetB
# Источник: RFC 7836, Appendix A.1 (каноническая форма Weierstrass)
TC26_512_B = Curve(
    name = 'tc26-512-B',
    p  = 0x008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F,
    a  = 0x008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C,  # p - 3
    b  = 0x687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116,
    q  = 0x00800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD,
    gx = 0x02,
    gy = 0x1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD,
    validate = False,
)

# id-tc26-gost-3410-2012-512-paramSetC
# Источник: RFC 7836, Appendix A.2 (twisted-Edwards-форма;
# здесь используются эквивалентные Weierstrass-параметры a, b, x, y).
TC26_512_C = Curve(
    name = 'tc26-512-C',
    p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7,
    a  = 0xDC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3,
    b  = 0xB4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1,
    q  = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED,
    gx = 0xE2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148,
    gy = 0xF5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F,
    validate = False,
)

# ---------------------------------------------------------------------------
# Реестр: имя → объект кривой
# ---------------------------------------------------------------------------

# Тестовые наборы — validate=True (быстрые, 256/512-бит)
# Стандартные наборы — validate=False
# Для проверки используйте curve.validate() или test_curve_params()

PARAMSETS: dict[str, Curve] = {
    # Тестовые наборы из Приложения А ГОСТ Р 34.10-2012
    'test-256':    GOST256_TEST,
    'test-512':    GOST512_TEST,

    # Стандартные 256-битные наборы TC26
    'tc26-256-A':  TC26_256_A,
    'tc26-256-B':  TC26_256_B,
    'tc26-256-C':  TC26_256_C,
    'tc26-256-D':  TC26_256_D,

    # Стандартные 256-битные наборы CryptoPro
    'cryptopro-A': CRYPTOPRO_A,
    'cryptopro-B': CRYPTOPRO_B,
    'cryptopro-C': CRYPTOPRO_C,

    # Стандартные 512-битные наборы TC26
    'tc26-512-A':  TC26_512_A,
    'tc26-512-B':  TC26_512_B,
    'tc26-512-C':  TC26_512_C,
}
