class FCSR():
    def __init__(self, q: int, m: int, a: int):
        coefficients = self.int_to_bit_seq(q + 1)[::-1]
        state = self.int_to_bit_seq(a)[:len(coefficients)-1]
        state = [0] * (len(coefficients) - len(state) - 1) + state
        state = state[::-1]

        self.m = m
        self.q = coefficients
        self.a = state

    @staticmethod
    def int_to_bit_seq(number: int) -> list[int]:
        return list(map(int, list(bin(number)[2:])))

    def clock(self) -> int:
        comp = self.m + sum([x & y for (x, y) in zip(self.q[1:], self.a[::-1])])
        self.a.append(comp % 2)
        self.m = comp // 2

        return self.a.pop(0)

    def get_idx(self, idx_length: int) -> int:
        ret = 0

        for _ in range(idx_length):
            bit = self.clock()
            ret = (ret << 1) | bit

        return ret
