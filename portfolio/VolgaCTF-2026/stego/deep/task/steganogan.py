# -*- coding: utf-8 -*-
import argparse
from collections import Counter

import numpy as np
import torch
from PIL import Image
from reedsolo import RSCodec
from torch import nn

print('=' * 80)
print('SteganoGAN inference script')
print('Adapted from https://github.com/DAI-Lab/SteganoGAN')
print('Paper: Zhang et al. SteganoGAN: High Capacity Image Steganography with GANs. https://arxiv.org/abs/1901.03892')
print('=' * 80)


# region Models

def _conv2d(in_channels, out_channels, kernel_size=3, padding=1):
    return nn.Conv2d(
        in_channels=in_channels,
        out_channels=out_channels,
        kernel_size=kernel_size,
        padding=padding
    )


class DenseEncoder(nn.Module):
    def __init__(self, data_depth, hidden_size):
        super().__init__()
        self.data_depth = data_depth
        self.hidden_size = hidden_size
        self._models = self._build_models()

    def _build_models(self):
        self.conv1 = nn.Sequential(
            _conv2d(3, self.hidden_size),
            nn.LeakyReLU(inplace=True),
            nn.BatchNorm2d(self.hidden_size),
        )
        self.conv2 = nn.Sequential(
            _conv2d(self.hidden_size + self.data_depth, self.hidden_size),
            nn.LeakyReLU(inplace=True),
            nn.BatchNorm2d(self.hidden_size),
        )
        self.conv3 = nn.Sequential(
            _conv2d(self.hidden_size * 2 + self.data_depth, self.hidden_size),
            nn.LeakyReLU(inplace=True),
            nn.BatchNorm2d(self.hidden_size),
        )
        self.conv4 = nn.Sequential(
            _conv2d(self.hidden_size * 3 + self.data_depth, 3)
        )

        return self.conv1, self.conv2, self.conv3, self.conv4

    def forward(self, image, data):
        x = self._models[0](image)
        x_list = [x]
        for layer in self._models[1:]:
            x = layer(torch.cat(x_list + [data], dim=1))
            x_list.append(x)

        return image + x


class DenseDecoder(nn.Module):
    def __init__(self, data_depth, hidden_size):
        super().__init__()
        self.data_depth = data_depth
        self.hidden_size = hidden_size
        self._models = self._build_models()

    def _build_models(self):
        self.conv1 = nn.Sequential(
            _conv2d(3, self.hidden_size),
            nn.LeakyReLU(inplace=True),
            nn.BatchNorm2d(self.hidden_size),
        )
        self.conv2 = nn.Sequential(
            _conv2d(self.hidden_size, self.hidden_size),
            nn.LeakyReLU(inplace=True),
            nn.BatchNorm2d(self.hidden_size),
        )
        self.conv3 = nn.Sequential(
            _conv2d(self.hidden_size * 2, self.hidden_size),
            nn.LeakyReLU(inplace=True),
            nn.BatchNorm2d(self.hidden_size)
        )
        self.conv4 = nn.Sequential(
            _conv2d(self.hidden_size * 3, self.data_depth)
        )

        return self.conv1, self.conv2, self.conv3, self.conv4

    def forward(self, x):
        x = self._models[0](x)
        if len(self._models) > 1:
            x_list = [x]
            for layer in self._models[1:]:
                x = layer(torch.cat(x_list, dim=1))
                x_list.append(x)

        return x


# endregion Models

# region Embedding and extracting

def make_payload(width: int, height: int, depth: int, message: str, rs: RSCodec):
    # encode the input text
    data = message.encode('utf-8')
    x = rs.encode(bytearray(data))
    data_bits = list(np.unpackbits(np.array(bytearray(x), dtype=np.uint8), bitorder='big'))

    # append end of message marker
    message = data_bits + [0] * 32

    # make the payload
    payload = message
    while len(payload) < width * height * depth:
        payload += message

    payload = payload[:width * height * depth]

    return torch.FloatTensor(payload).view(1, depth, height, width)


def encode(
        stego_image_path: str,
        cover_image_path: str,
        message: str,
        encoder: DenseEncoder,
        device: str,
        rs: RSCodec):
    # read the cover image
    image = Image.open(cover_image_path)
    cover = np.array(image, dtype=np.float32)
    cover = cover / 127.5 - 1.0
    cover = torch.FloatTensor(cover).permute(2, 0, 1).unsqueeze(0)

    # make the payload to embed
    cover_size = cover.size()
    payload = make_payload(cover_size[3], cover_size[2], encoder.data_depth, message, rs)

    # embed the payload
    cover = cover.to(device)
    payload = payload.to(device)
    generated = encoder(cover, payload)[0].clamp(-1.0, 1.0)

    # save the stego image
    generated = (generated.permute(1, 2, 0).detach().cpu().numpy() + 1.0) * 127.5
    Image.fromarray(generated.astype(np.uint8)).save(stego_image_path)


def decode(stego_image_path: str, decoder: DenseDecoder, device: str, rs: RSCodec):
    # read the stego image
    image = Image.open(stego_image_path)
    stego = np.array(image, dtype=np.float32)
    # stego = stego / 255.0
    stego = stego / 127.5 - 1.0
    stego = torch.FloatTensor(stego).permute(2, 0, 1).unsqueeze(0)

    # decode the image
    stego = stego.to(device)
    stego = decoder(stego).view(-1) > 0

    # split and decode messages
    marker = b'\x00\x00\x00\x00'
    bits = stego.data.int().cpu().numpy().tolist()
    ints = bytearray(np.packbits(bits, bitorder='big'))
    splits = ints.split(marker)

    candidates = Counter()
    for candidate in splits:
        try:
            text = rs.decode(candidate)
            candidate = text[0].decode("utf-8")
            if candidate:
                candidates[candidate] += 1
        except BaseException:
            pass

    # choose most common message
    if len(candidates) == 0:
        raise ValueError('Failed to extract any message')

    candidate, count = candidates.most_common(1)[0]
    return candidate


# endregion Embedding and extracting


if __name__ == '__main__':
    # 1. parse cmd args
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='cmd', help='Cmd to execute, one of "embed", "extract"')

    parser.add_argument('--data-depth', type=int, default=1, help='Data depth, default is 1')
    parser.add_argument('--hidden-size', type=int, default=32, help='Hidden space dim, default is 32')
    parser.add_argument('--rs-nsym', type=int, default=250, help='Number of ecc symbols in RS')
    parser.add_argument('--rs-nsize', type=int, default=255, help='Maximum length of each chunk in RS')
    parser.add_argument('--device', type=str, default=None, help='GPU ID')

    parser_embed = subparsers.add_parser('embed', help='Embed message')
    parser_embed.add_argument('input', type=str, help='Path to cover image')
    parser_embed.add_argument('message', type=str, help='Message to be embedded')
    parser_embed.add_argument('output', type=str, help='Path to stego image')
    parser_embed.add_argument('-m', '--model-path', type=str, default='./encoder.pt',
                              help='Path to the model, default is "./encoder.pt"')

    parser_ext = subparsers.add_parser('extract', help='Extract message')
    parser_ext.add_argument('input', type=str, help='Path to stego image')
    parser_ext.add_argument('-m', '--model-path', type=str, default='./decoder.pt',
                            help='Path to the model, default is "./decoder.pt"')

    args = parser.parse_args()

    # 2. execute the cmd
    rs = RSCodec(nsym=args.rs_nsym, nsize=args.rs_nsize)
    if args.device is None:
        args.device = 'cuda:0' if torch.cuda.is_available() else 'cpu'

    if args.cmd == 'embed':
        encoder = DenseEncoder(args.data_depth, args.hidden_size)
        encoder.load_state_dict(torch.load(args.model_path, map_location='cpu'))
        encoder.to(device=args.device)
        torch.set_grad_enabled(False)

        encode(args.output, args.input, args.message, encoder, args.device, rs=rs)

    elif args.cmd == 'extract':
        decoder = DenseDecoder(args.data_depth, args.hidden_size)
        decoder.load_state_dict(torch.load(args.model_path, map_location='cpu'))
        decoder.to(device=args.device)
        torch.set_grad_enabled(False)

        extracted = decode(args.input, decoder, args.device, rs=rs)
        print(extracted)

    else:
        raise ValueError('Unknown cmd "%s"' % args.cmd)
