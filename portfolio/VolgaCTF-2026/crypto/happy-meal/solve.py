MNEMONIC_DICT_EN = [
    "apple", "actor", "animal", "airport", "answer",
    "ball", "banana", "beach", "bedroom", "bird",
    "cable", "camera", "candle", "carpet", "castle",
    "damage", "dance", "desert", "diamond", "doctor",
    "eagle", "earth", "economy", "editor", "engine",
    "factory", "family", "farmer", "feather", "festival",
    "galaxy", "garden", "gas", "gate", "guitar",
    "hair", "hammer", "happy", "helmet", "holiday",
    "ice", "idea", "income", "insect", "island",
    "jacket", "jelly", "jewel", "journey", "judge",
    "kangaroo", "kayak", "kernel", "kettle", "king",
    "ladder", "lake", "language", "lawyer", "library",
    "machine", "magazine", "market", "meal", "museum",
    "nail", "nation", "necklace", "needle", "notebook",
    "oasis", "ocean", "office", "onion", "orange",
    "package", "painting", "palace", "parent", "planet",
    "quarry", "queen", "question", "queue",
    "rabbit", "radio", "rainbow", "river", "robot",
    "salary", "sandwich", "school", "screen", "sister",
    "table", "teacher", "temple", "theory", "ticket",
    "umbrella", "uncle", "unicorn", "uniform", "university",
    "vacation", "valley", "vessel", "victory", "village",
    "wallet", "warrior", "weather", "window", "writer",
    "xenon", "xylophone", "xylem", "xenophobia",
    "yacht", "yak", "yard", "year", "youth",
    "zebra", "zenith", "zinc", "zoo", "zone",
]

class FCSR:
    def __init__(self, q: int, m: int, a: int):
        self.q_int = q
        self.m_init = m
        self.a_int = a
        coefficients = list(map(int, list(bin(q + 1)[2:])))[::-1]
        state = list(map(int, list(bin(a)[2:])))[:len(coefficients)-1]
        state = [0] * (len(coefficients) - len(state) - 1) + state
        state = state[::-1]

        self.m = m
        self.q = coefficients
        self.a = state

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


known_bits = [0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0]

def int_to_bit_seq(n):
    return [int(x) for x in bin(n)[2:]]

print("Starting brute force...")
for q in range(1, 10000, 2):  # q is odd
    q_bin = bin(q+1)[2:]
    coeffs = [int(x) for x in q_bin][::-1]
    
    max_m = sum(coeffs) - 1
    if max_m <= 0:
        continue
        
    for a in range(q + 2):
        state_orig = [int(x) for x in bin(a)[2:]][:len(coeffs)-1]
        state_orig = [0] * (len(coeffs) - len(state_orig) - 1) + state_orig
        state_orig = state_orig[::-1]
        
        for m_orig in range(max_m):
            m = m_orig
            a_state = list(state_orig)
            
            match = True
            for expected_bit in known_bits:
                comp = m
                for x, y in zip(coeffs[1:], a_state[::-1]):
                    comp += x & y
                a_state.append(comp % 2)
                m = comp // 2
                
                if a_state.pop(0) != expected_bit:
                    match = False
                    break
            
            if match:
                fcsr = FCSR(q, m_orig, a)
                phrase = ' '.join(MNEMONIC_DICT_EN[fcsr.get_idx(7)] for _ in range(12))
                print(f"Found match: q={q}, a={a}, m={m_orig} -> Phrase: {phrase}")
