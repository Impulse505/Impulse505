import torch
import numpy as np
from PIL import Image
from torch import nn
from torch.nn.functional import binary_cross_entropy_with_logits
from torch.optim import Adam
from collections import Counter
from reedsolo import RSCodec

# ---- Architecture (from steganogan.py) ----
def _conv2d(in_c, out_c, k=3, p=1):
    return nn.Conv2d(in_c, out_c, k, padding=p)

class DenseEncoder(nn.Module):
    def __init__(self, data_depth=1, hidden_size=32):
        super().__init__()
        self.data_depth = data_depth
        self.hidden_size = hidden_size
        self.conv1 = nn.Sequential(_conv2d(3, hidden_size), nn.LeakyReLU(True), nn.BatchNorm2d(hidden_size))
        self.conv2 = nn.Sequential(_conv2d(hidden_size + data_depth, hidden_size), nn.LeakyReLU(True), nn.BatchNorm2d(hidden_size))
        self.conv3 = nn.Sequential(_conv2d(hidden_size * 2 + data_depth, hidden_size), nn.LeakyReLU(True), nn.BatchNorm2d(hidden_size))
        self.conv4 = nn.Sequential(_conv2d(hidden_size * 3 + data_depth, 3))
        self._models = (self.conv1, self.conv2, self.conv3, self.conv4)

    def forward(self, image, data):
        x = self._models[0](image)
        x_list = [x]
        for layer in self._models[1:]:
            x = layer(torch.cat(x_list + [data], dim=1))
            x_list.append(x)
        return image + x

class DenseDecoder(nn.Module):
    def __init__(self, data_depth=1, hidden_size=32):
        super().__init__()
        self.data_depth = data_depth
        self.hidden_size = hidden_size
        self.conv1 = nn.Sequential(_conv2d(3, hidden_size), nn.LeakyReLU(True), nn.BatchNorm2d(hidden_size))
        self.conv2 = nn.Sequential(_conv2d(hidden_size, hidden_size), nn.LeakyReLU(True), nn.BatchNorm2d(hidden_size))
        self.conv3 = nn.Sequential(_conv2d(hidden_size * 2, hidden_size), nn.LeakyReLU(True), nn.BatchNorm2d(hidden_size))
        self.conv4 = nn.Sequential(_conv2d(hidden_size * 3, data_depth))
        self._models = (self.conv1, self.conv2, self.conv3, self.conv4)

    def forward(self, x):
        x = self._models[0](x)
        x_list = [x]
        for layer in self._models[1:]:
            x = layer(torch.cat(x_list, dim=1))
            x_list.append(x)
        return x

# ---- Load Encoder ----
# Assume 'encoder.pt' is present in the challenge directory
encoder = DenseEncoder(1, 32)
# encoder.load_state_dict(torch.load('encoder.pt', map_location='cpu'))

# ---- Decoder Retraining Logic ----
def train_decoder(stego_path, encoder_path):
    encoder.load_state_dict(torch.load(encoder_path, map_location='cpu'))
    encoder.eval()
    for p in encoder.parameters():
        p.requires_grad = False

    decoder = DenseDecoder(1, 32)
    optimizer = Adam(decoder.parameters(), lr=1e-4)

    stego_np = np.array(Image.open(stego_path), dtype=np.float32) / 127.5 - 1.0
    H, W = stego_np.shape[:2]
    PATCH = 360

    print("Training decoder based on encoder's deterministic behavior...")
    for step in range(2001):
        y = np.random.randint(0, max(1, H - PATCH))
        x = np.random.randint(0, max(1, W - PATCH))
        crop = stego_np[y:y+PATCH, x:x+PATCH] if H > PATCH and W > PATCH else stego_np
        cover = torch.FloatTensor(crop).permute(2,0,1).unsqueeze(0)
        _, _, h, w = cover.size()
        data = torch.zeros((1, 1, h, w)).random_(0, 2)
        
        with torch.no_grad():
            generated = encoder(cover, data)
        
        decoded = decoder(generated)
        loss = binary_cross_entropy_with_logits(decoded, data)
        
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        if step % 200 == 0:
            acc = (decoded >= 0.0).eq(data >= 0.5).float().mean().item()
            print(f"Step {step:4d}: loss={loss.item():.4f}, acc={acc:.4f}")

    # Extract Flag
    print("\nExtracting flag from target stego image...")
    stego_full = torch.FloatTensor(stego_np).permute(2,0,1).unsqueeze(0)
    decoder.eval()
    with torch.no_grad():
        bits_raw = decoder(stego_full).view(-1) > 0
    
    bits = bits_raw.data.int().cpu().numpy().tolist()
    ints = bytearray(np.packbits(bits, bitorder='big'))

    for nsym in [250, 10, 20, 40]:
        try:
            rs = RSCodec(nsym=nsym, nsize=255)
            marker = b'\x00\x00\x00\x00'
            splits = ints.split(marker)
            candidates = Counter()
            for candidate in splits:
                try:
                    text = rs.decode(candidate)
                    s = text[0].decode('utf-8')
                    if s: candidates[s] += 1
                except: pass
            if candidates:
                flag = candidates.most_common(1)[0][0]
                print(f"[nsym={nsym}] FLAG: {flag}")
                break
        except: pass

if __name__ == "__main__":
    train_decoder('stego.png', 'encoder.pt')
