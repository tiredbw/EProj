"""Адрес ADRS (раздел 4.4): 224 бита = 28 байт в порядке big-endian.

Уровень (4 байта) ‖ Дерево (8) ‖ Тип (4) ‖ Ключ (4) ‖ суффикс (4 + 4).
Первое слово суффикса — цепочка или высота, второе — элемент или индекс
(рисунки 2–9).
"""

WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
SIGN_MSG_WOTS = 5
WOTS_PRF = 6
FORS_PRF = 7


class Address:
    def __init__(self):
        self.layer = 0
        self.tree = 0
        self.type = 0
        self.keypair = 0
        self.word1 = 0
        self.word2 = 0

    def to_bytes(self) -> bytes:
        return (self.layer.to_bytes(4, "big") + self.tree.to_bytes(8, "big")
                + self.type.to_bytes(4, "big") + self.keypair.to_bytes(4, "big")
                + self.word1.to_bytes(4, "big") + self.word2.to_bytes(4, "big"))

    def set_layer(self, x: int) -> None:
        self.layer = x

    def set_tree(self, x: int) -> None:
        self.tree = x

    def set_type(self, t: int) -> None:
        """УстановитьТип меняет только поле «Тип», остальные поля сохраняются."""
        self.type = t

    def set_keypair(self, x: int) -> None:
        self.keypair = x

    def set_suffix(self, x: int) -> None:
        self.word1, self.word2 = x >> 32, x & 0xFFFFFFFF

    def set_chain(self, x: int) -> None:
        self.word1 = x

    def set_element(self, x: int) -> None:
        self.word2 = x

    def set_height(self, x: int) -> None:
        self.word1 = x

    def set_index(self, x: int) -> None:
        self.word2 = x

    def get_height(self) -> int:
        return self.word1

    def get_index(self) -> int:
        return self.word2
