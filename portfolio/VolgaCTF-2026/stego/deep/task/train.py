# -*- coding: utf-8 -*-
import argparse
import gc
import json
import os
import time
from datetime import datetime
from math import exp

import numpy as np
import torch
from PIL import Image
from torch import nn, conv2d
from torch.nn.functional import mse_loss, binary_cross_entropy_with_logits
from torch.optim import Adam
from torch.utils.data import DataLoader
from torchvision import datasets, transforms
from tqdm import tqdm

print('=' * 80)
print('SteganoGAN training script')
print('Adapted from https://github.com/DAI-Lab/SteganoGAN')
print('Paper: Zhang et al. SteganoGAN: High Capacity Image Steganography with GANs. https://arxiv.org/abs/1901.03892')
print('=' * 80)


# region Utils

# region SSIM implementation

def gaussian(window_size, sigma):
    _exp = [exp(-(x - window_size // 2) ** 2 / float(2 * sigma ** 2)) for x in range(window_size)]
    gauss = torch.Tensor(_exp)
    return gauss / gauss.sum()


def create_window(window_size, channel):
    _1D_window = gaussian(window_size, 1.5).unsqueeze(1)
    _2D_window = _1D_window.mm(_1D_window.t()).float().unsqueeze(0).unsqueeze(0)
    window = _2D_window.expand(channel, 1, window_size, window_size).contiguous()
    return window


def _ssim(img1, img2, window, window_size, channel, size_average=True):
    padding_size = window_size // 2

    mu1 = conv2d(img1, window, padding=padding_size, groups=channel)
    mu2 = conv2d(img2, window, padding=padding_size, groups=channel)

    mu1_sq = mu1.pow(2)
    mu2_sq = mu2.pow(2)
    mu1_mu2 = mu1 * mu2

    sigma1_sq = conv2d(img1 * img1, window, padding=padding_size, groups=channel) - mu1_sq
    sigma2_sq = conv2d(img2 * img2, window, padding=padding_size, groups=channel) - mu2_sq
    sigma12 = conv2d(img1 * img2, window, padding=padding_size, groups=channel) - mu1_mu2

    C1 = 0.01 ** 2
    C2 = 0.03 ** 2

    _ssim_quotient = ((2 * mu1_mu2 + C1) * (2 * sigma12 + C2))
    _ssim_divident = ((mu1_sq + mu2_sq + C1) * (sigma1_sq + sigma2_sq + C2))

    ssim_map = _ssim_quotient / _ssim_divident

    if size_average:
        return ssim_map.mean()
    else:
        return ssim_map.mean(1).mean(1).mean(1)


def ssim(img1, img2, window_size=11, size_average=True):
    (_, channel, _, _) = img1.size()
    window = create_window(window_size, channel)

    if img1.is_cuda:
        window = window.cuda(img1.get_device())
    window = window.type_as(img1)

    return _ssim(img1, img2, window, window_size, channel, size_average)


# endregion SSIM implementation

# endregion Utils

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


class BasicCritic(nn.Module):
    def __init__(self, hidden_size):
        super().__init__()
        self.hidden_size = hidden_size
        self._models = self._build_models()

    def _build_models(self):
        return nn.Sequential(
            _conv2d(3, self.hidden_size),
            nn.LeakyReLU(inplace=True),
            nn.BatchNorm2d(self.hidden_size),

            _conv2d(self.hidden_size, self.hidden_size),
            nn.LeakyReLU(inplace=True),
            nn.BatchNorm2d(self.hidden_size),

            _conv2d(self.hidden_size, self.hidden_size),
            nn.LeakyReLU(inplace=True),
            nn.BatchNorm2d(self.hidden_size),

            _conv2d(self.hidden_size, 1)
        )

    def forward(self, x):
        x = self._models(x)
        x = torch.mean(x.view(x.size(0), -1), dim=1)

        return x


# endregion Models

# region Training

METRIC_FIELDS = [
    'val.encoder_mse',
    'val.decoder_loss',
    'val.decoder_acc',
    'val.cover_score',
    'val.generated_score',
    'val.ssim',
    'val.psnr',
    'val.bpp',
    'train.encoder_mse',
    'train.decoder_loss',
    'train.decoder_acc',
    'train.cover_score',
    'train.generated_score',
]


def train(
        dataset_train_path: str,
        dataset_val_path: str,
        data_depth: int,
        hidden_size: int,
        learning_rate: float = 1e-4,
        batch_size: int = 4,
        seed: int = 42,
        n_epochs: int = 5,
        device: str = 'cuda:0',
        log_folder_path: str = None,
        verbose: bool = False):
    # 1. make sure the log folder exists
    samples_folder_path = None
    if log_folder_path:
        os.makedirs(log_folder_path, exist_ok=True)
        samples_folder_path = os.path.join(log_folder_path, 'samples')
        os.makedirs(samples_folder_path, exist_ok=True)

    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
    torch.manual_seed(seed)

    # 2. init Datasets and Dataloaders
    mu = [.5, .5, .5]
    sigma = [.5, .5, .5]
    transform = transforms.Compose([
        transforms.RandomHorizontalFlip(),
        transforms.RandomCrop(360, pad_if_needed=True),
        transforms.ToTensor(),
        transforms.Normalize(mu, sigma)
    ])

    train_set = datasets.ImageFolder(dataset_train_path, transform=transform)
    train_loader = torch.utils.data.DataLoader(train_set, batch_size=batch_size, shuffle=True)

    val_set = datasets.ImageFolder(dataset_val_path, transform=transform)
    val_loader = DataLoader(val_set, batch_size=batch_size, shuffle=False)

    # 3. init the models and the optimizers
    encoder = DenseEncoder(data_depth, hidden_size)
    decoder = DenseDecoder(data_depth, hidden_size)
    critic = BasicCritic(hidden_size)

    use_gpu = False
    if device is not None and device != 'cpu':
        use_gpu = True
        encoder.to(device)
        decoder.to(device)
        critic.to(device)

    critic_optimizer = Adam(critic.parameters(), lr=learning_rate)
    enc_dec_optimizer = Adam(list(decoder.parameters()) + list(encoder.parameters()), lr=learning_rate)

    # 4. define helper functions
    def gen_random_data(cover):
        n, _, h, w = cover.size()
        return torch.zeros((n, data_depth, h, w), device=device).random_(0, 2)

    def encode_decode(cover, quantize=False):
        payload = gen_random_data(cover)
        generated = encoder(cover, payload)
        if quantize:
            generated = (255.0 * (generated + 1.0) / 2.0).long()
            generated = 2.0 * generated.float() / 255.0 - 1.0

        decoded = decoder(generated)

        return generated, payload, decoded

    def fit_critic(_train, _metrics):
        batch_times = []
        start_time = time.time()
        for cover, _ in tqdm(_train, disable=not verbose):
            gc.collect()
            start_batch_time = time.time()

            cover = cover.to(device)
            payload = gen_random_data(cover)
            generated = encoder(cover, payload)
            cover_score = torch.mean(critic(cover))
            generated_score = torch.mean(critic(generated))

            critic_optimizer.zero_grad()
            (cover_score - generated_score).backward(retain_graph=False)
            critic_optimizer.step()

            for p in critic.parameters():
                p.data.clamp_(-0.1, 0.1)

            batch_times.append(time.time() - start_batch_time)

            _metrics['train.cover_score'].append(cover_score.item())
            _metrics['train.generated_score'].append(generated_score.item())

        elapsed_time = time.time() - start_time
        mean_batch_time = float(np.mean(np.array(batch_times)))
        return mean_batch_time, elapsed_time

    def fit_coders(_train, _metrics):
        batch_times = []
        start_time = time.time()
        for cover, _ in tqdm(_train, disable=not verbose):
            gc.collect()
            start_batch_time = time.time()

            cover = cover.to(device)
            generated, payload, decoded = encode_decode(cover, quantize=False)

            encoder_mse = mse_loss(generated, cover)
            decoder_loss = binary_cross_entropy_with_logits(decoded, payload)
            decoder_acc = (decoded >= 0.0).eq(payload >= 0.5).sum().float() / payload.numel()
            generated_score = torch.mean(critic(generated))

            enc_dec_optimizer.zero_grad()
            (100.0 * encoder_mse + decoder_loss + generated_score).backward()
            enc_dec_optimizer.step()

            batch_times.append(time.time() - start_batch_time)

            _metrics['train.encoder_mse'].append(encoder_mse.item())
            _metrics['train.decoder_loss'].append(decoder_loss.item())
            _metrics['train.decoder_acc'].append(decoder_acc.item())

        elapsed_time = time.time() - start_time
        mean_batch_time = float(np.mean(np.array(batch_times)))
        return mean_batch_time, elapsed_time

    def validate(_validate, _metrics):
        batch_times = []
        start_time = time.time()
        for cover, _ in tqdm(_validate, disable=not verbose):
            gc.collect()
            start_batch_time = time.time()

            cover = cover.to(device)
            generated, payload, decoded = encode_decode(cover, quantize=True)

            encoder_mse = mse_loss(generated, cover)
            decoder_loss = binary_cross_entropy_with_logits(decoded, payload)
            decoder_acc = (decoded >= 0.0).eq(payload >= 0.5).sum().float() / payload.numel()

            generated_score = torch.mean(critic(generated))
            cover_score = torch.mean(critic(cover))

            batch_times.append(time.time() - start_batch_time)

            _metrics['val.encoder_mse'].append(encoder_mse.item())
            _metrics['val.decoder_loss'].append(decoder_loss.item())
            _metrics['val.decoder_acc'].append(decoder_acc.item())
            _metrics['val.cover_score'].append(cover_score.item())
            _metrics['val.generated_score'].append(generated_score.item())
            _metrics['val.ssim'].append(ssim(cover, generated).item())
            _metrics['val.psnr'].append(10 * torch.log10(4 / encoder_mse).item())
            _metrics['val.bpp'].append(data_depth * (2 * decoder_acc.item() - 1))

        elapsed_time = time.time() - start_time
        mean_batch_time = float(np.mean(np.array(batch_times)))
        return mean_batch_time, elapsed_time

    def generate_samples(samples_path, cover, epoch):
        cover = cover.to(device)
        generated, payload, decoded = encode_decode(cover, quantize=False)
        for sample in range(generated.size(0)):
            cover_path = os.path.join(samples_path, '{}.cover.png'.format(sample))
            sample_name = '{}.generated-{:2d}.png'.format(sample, epoch)
            sample_path = os.path.join(samples_path, sample_name)

            image = (cover[sample].permute(1, 2, 0).detach().cpu().numpy() + 1.0) / 2.0
            im = Image.fromarray((255.0 * image).astype('uint8'))
            im.save(cover_path)

            sampled = generated[sample].clamp(-1.0, 1.0).permute(1, 2, 0)
            sampled = sampled.detach().cpu().numpy() + 1.0

            image = sampled / 2.0
            im = Image.fromarray((255.0 * image).astype('uint8'))
            im.save(sample_path)

    # 5. start the training
    sample_cover = None
    if log_folder_path:
        sample_cover = next(iter(val_loader))[0]

    history = []
    best_bpp = 0.0
    for epoch in range(1, n_epochs + 1):
        # log the progress
        start_epoch_time = time.time()
        if verbose:
            print('Epoch {}/{}'.format(epoch, n_epochs))

        # make a step
        metrics = {field: list() for field in METRIC_FIELDS}

        fit_times_critic = fit_critic(train_loader, metrics)
        fit_times_coders = fit_coders(train_loader, metrics)
        val_times = validate(val_loader, metrics)

        # save the current checkpoint
        if log_folder_path:
            fit_metrics = {k: sum(v) / len(v) for k, v in metrics.items()}
            fit_metrics['epoch'] = epoch
            history.append(fit_metrics)

            metrics_path = os.path.join(log_folder_path, 'metrics.log')
            with open(metrics_path, 'w') as metrics_file:
                json.dump(history, metrics_file, indent=4)

            fmt = '{}.bpp-{:03f}.{{0}}.pt'.format(epoch, fit_metrics['val.bpp'])
            torch.save(encoder.state_dict(), os.path.join(log_folder_path, fmt.format('encoder')))
            torch.save(decoder.state_dict(), os.path.join(log_folder_path, fmt.format('decoder')))
            torch.save({
                'encoder': encoder.state_dict(),
                'decoder': decoder.state_dict(),
                'critic': critic.state_dict(),
                'enc_dec_optimizer': enc_dec_optimizer.state_dict(),
                'cr_optimizer': critic_optimizer.state_dict(),
                'metrics': metrics,
                'train_epoch': epoch,
                'date': datetime.now().strftime("%Y-%m-%d_%H:%M:%S"),
            }, os.path.join(log_folder_path, fmt.format('training')))

            if best_bpp < fit_metrics['val.bpp']:
                best_bpp = fit_metrics['val.bpp']
                torch.save(encoder.state_dict(), os.path.join(log_folder_path, 'encoder.pt'))
                torch.save(decoder.state_dict(), os.path.join(log_folder_path, 'decoder.pt'))

            generate_samples(samples_folder_path, sample_cover, epoch)

        # log the progress
        epoch_time = time.time() - start_epoch_time
        print('Training times')
        print('..epoch time:      %.3f sec' % epoch_time)
        print('..critic time:     mean=%.3f sec, total=%.3f' % fit_times_critic)
        print('..coders time:     mean=%.3f sec, total=%.3f' % fit_times_coders)
        print('..validation time: mean=%.3f sec, total=%.3f' % val_times)
        print('')
        print('Metrics')
        print('..Train')
        print('....encoder: mse=%.7f' % fit_metrics['train.encoder_mse'])
        print('....decoder: loss=%.7f acc=%.7f' % (fit_metrics['train.decoder_loss'], fit_metrics['train.decoder_acc']))
        print('..Validation')
        print('....encoder: mse=%.7f' % fit_metrics['val.encoder_mse'])
        print('....decoder: loss=%.7f acc=%.7f' % (fit_metrics['val.decoder_loss'], fit_metrics['val.decoder_acc']))
        print('....iq:      ssim=%.7f psnr=%.7f' % (fit_metrics['val.ssim'], fit_metrics['val.psnr']))
        print('....bpp:     %.7f' % fit_metrics['val.bpp'])
        print('')

        # empty cuda cache and trigger the GC (most likely this is useless, but won't hurt anyway)
        if use_gpu:
            torch.cuda.empty_cache()
        gc.collect()


# endregion Training


if __name__ == '__main__':
    # 1. parse cmd args
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dataset', type=str, default='./PascalVOC', help='Path to dataset')
    parser.add_argument('-o', '--output', type=str, default=None, help='Path to output folder')
    parser.add_argument('--data-depth', type=int, default=1, help='Data depth, default is 1')
    parser.add_argument('--hidden-size', type=int, default=32, help='Hidden space dim, default is 32')
    parser.add_argument('--learning-rate', type=float, default=1e-4, help='Learning rate')
    parser.add_argument('--batch-size', type=int, default=4, help='Batch size')
    parser.add_argument('--seed', type=int, default=42, help='Seed for the PRNG')
    parser.add_argument('--epochs', type=int, default=5, help='Number of epochs')
    parser.add_argument('--device', type=str, default='cuda:0', help='GPU ID')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # 2. execute training
    if args.output is None:
        dataset_basename = os.path.basename(args.dataset)
        args.output = os.path.join('.', '{0}-{1}'.format(dataset_basename, args.seed))

    train(
        dataset_train_path=os.path.join(args.dataset, 'train'),
        dataset_val_path=os.path.join(args.dataset, 'val'),
        data_depth=args.data_depth,
        hidden_size=args.hidden_size,
        learning_rate=args.learning_rate,
        batch_size=args.batch_size,
        seed=args.seed,
        n_epochs=args.epochs,
        device=args.device,
        log_folder_path=args.output,
        verbose=args.verbose
    )
