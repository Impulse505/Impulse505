# Deep (Stegano) — VolgaCTF 2026

## English

### Challenge Description
The **Deep** challenge was a steganography task based on **SteganoGAN**, a Generative Adversarial Network (GAN) designed to hide data within images. I was given a target image (`stego.png`), a script for embedding/extracting data (`steganogan.py`), and the weights for the **encoder** (`encoder.pt`). However, the **decoder** (`decoder.pt`) required to extract the flag was missing.

### Vulnerability Analysis
- **SteganoGAN Architecture**: SteganoGAN uses a triplets of networks: a `DenseEncoder` to hide the message, a `DenseDecoder` to extract it, and a `BasicCritic` to evaluate the quality of the stego image.
- **Deterministic Encoder**: Since I had the `encoder.pt` file, I could theoretically generate an infinite number of training pairs: `(stego_image, hidden_data)`.
- **Decoder Retraining**: By fixing the weights of the encoder and using the known architecture of the `DenseDecoder`, I could train a new decoder from scratch to "learn" how to undo the specific transformations applied by the given encoder.

### Exploitation Strategy
1.  **Architecture Recovery**: I identified the `DenseDecoder` architecture from the provided `steganogan.py` and `train.py` scripts.
2.  **Synthetic Data Generation**: I used the `encoder.pt` to embed random bit strings into patches derived from the target `stego.png` (which served as a proxy for the original cover image).
3.  **Training**: I trained the new decoder for 2000 iterations until it achieved over 95% accuracy in reconstructing the hidden bits.
4.  **Extraction**: I applied the trained decoder to the full `stego.png` and decoded the message using the **Reed-Solomon** error correction parameters.

### Flag
`VolgaCTF{Th1s_m3ss@ge_wa$_d3eeply_embedded}`

---

## Russian

### Описание задания
Задание **Deep** — это задача на стеганографию, основанную на **SteganoGAN** (генеративно-состязательной сети для скрытия данных в изображениях). Мне были предоставлены: целевое изображение (`stego.png`), скрипт для обработки (`steganogan.py`) и веса **энкодера** (`encoder.pt`). Однако файл **декодера** (`decoder.pt`), необходимый для извлечения флага, отсутствовал.

### Анализ уязвимости
- **Архитектура SteganoGAN**: Система состоит из трех нейросетей: `DenseEncoder` (вшивает данные), `DenseDecoder` (извлекает их) и `BasicCritic` (оценивает незаметность изменений).
- **Детерминированный энкодер**: Имея на руках `encoder.pt`, я мог генерировать неограниченное количество пар данных `(стего-изображение, скрытые биты)`.
- **Дообучение (Retraining) декодера**: Зная архитектуру `DenseDecoder`, можно обучить новый декодер «с нуля», используя имеющийся энкодер как генератор обучающей выборки.

### Стратегия решения
1.  **Восстановление архитектуры**: На основе `steganogan.py` и `train.py` я воссоздал структуру `DenseDecoder`.
2.  **Генерация выборки**: Используя `encoder.pt`, я вшивал случайные битовые последовательности в участки (патчи) изображения `stego.png`.
3.  **Обучение**: Я обучил новый декодер на 2000 эпох, пока точность восстановления битов не превысила 95%.
4.  **Извлечение флага**: Применив обученную модель к исходному файлу `stego.png`, я получил битовую последовательность и декодировал её с помощью кода **Рида-Соломона**.

### Флаг
`VolgaCTF{Th1s_m3ss@ge_wa$_d3eeply_embedded}`
