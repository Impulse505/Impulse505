import math

from fcsr import FCSR
from dictionary import MNEMONIC_DICT_EN


if __name__ == '__main__':
    q = <HIDDEN>
    a = <HIDDEN>
    m = <HIDDEN>

    fcsr_generator = FCSR(q, m, a)

    idx_length = math.floor(math.log(len(MNEMONIC_DICT_EN), 2))

    mnemonic_phrase = ' '.join(
        MNEMONIC_DICT_EN[fcsr_generator.get_idx(idx_length)]
        for _ in range(12)
    )

    print(mnemonic_phrase)
