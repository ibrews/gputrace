#!/usr/bin/env python3
"""Offline reader for Xcode .gputrace packages -- no Xcode GPU debugger UI required.

Apple documents none of this; the container is an undocumented record stream tagged
"MTSP". The layout below was derived byte-by-byte from a visionOS capture (2026-08-25)
and has been exercised against UE 5.8.1 Metal captures.

Record layout (little-endian):
    u32  len          total bytes of this record
    i32  selector     negative id (stable within a trace; not a global name table)
    24B  reserved     observed all-zero
    u32  kind         small domain/class enum
    char sig[]        NUL-terminated, padded to 4 bytes.
                      'C'=u64 receiver  'S'=cstring  'u'/'i'=u32  'l'/'w'=u64  'b'=byte
    args              packed per sig

Files inside the package:
    device-resources-*   resource creation + labels + pixel-dump manifests
    capture              the submitted command stream (encoder labels, debug groups)
    MTLTexture-<id>-<n>-mipmap<m>-slice<s>   raw pixel dumps

Pixel dump layout (IMPORTANT -- two traps):
  * The payload is the TAIL of the file: offset = filesize - (height * bytesPerRow).
    In practice the header is 16384 bytes; do not hardcode it, derive it.
  * Depth+stencil dumps are PLANAR, not row-interleaved: a full float32 depth plane
    (h*w*4) followed by a full stencil plane (h*w). Reading them as interleaved rows
    of `bytesPerRow` "works" and silently produces a plausible image whose bottom
    ~20% is zero -- that is the stencil plane being misread, not missing depth.

Usage:
    python3 gputrace.py <trace.gputrace> textures        # labelled texture inventory
    python3 gputrace.py <trace.gputrace> encoders        # encoder + debug-group tree
    python3 gputrace.py <trace.gputrace> dump <label> <out.png>
    python3 gputrace.py <trace.gputrace> records <file> [filter]
    python3 gputrace.py <trace.gputrace> descriptors     # allocated size + storage mode
                                                          # per texture (only these two
                                                          # fields verified so far -- see
                                                          # SEL_TEX_* comments; sampleCount
                                                          # not yet decoded, don't assume)
"""
import glob
import os
import re
import struct
import sys

RECORD_FIXED_PREFIX = 36  # len + selector + 24 reserved bytes + kind
MIN_RECORD_LEN = 40       # fixed prefix + NUL-terminated signature padded to 4 bytes
MAX_RECORD_LEN = 1 << 24
SEL_SET_LABEL = 0xffffc090      # texture setLabel:
SEL_BUF_LABEL = 0xffffc00c      # buffer setLabel:
SEL_DUMP = 0xffffd804           # pixel-dump manifest entry
SEL_ENC_LABEL = 0xffffc067      # encoder label
SEL_DEBUG_GROUP = 0xffffc08c    # pushDebugGroup within an encoder
SEL_SCOPE = 0xffffc03d          # command-buffer level debug scope

# Per-texture creation-descriptor fields, keyed by the same pointer as SEL_SET_LABEL.
# Derived 2026-08-30 by correlating raw field values against ground truth read directly
# from Xcode's own Memory tab (Allocated Size / Storage Mode columns) for four textures
# spanning both states: ShadowDepthAtlas + MobileCSMAndSpotLightShadowmap (Shared, real
# byte sizes) vs SceneColorMS + SceneDepthZ (Memoryless MSAA, 0 bytes). Two independent
# matches each way -- confirmed, not guessed. sampleCount was NOT identified in this pass;
# no field examined correlates cleanly with 1/2/4/8 against texture identity. Don't assume
# it's decodable from the fields below -- it needs its own ground-truth anchor first.
SEL_TEX_ALLOCATED_SIZE = 0xffffd812   # sig='Cui', bytes; 0 for Memoryless (matches Xcode exactly)
SEL_TEX_STORAGE_MODE = 0xffffd823     # sig='Cui', empirical enum: 1=Shared, 2=Memoryless seen so
                                       # far (NOT Apple's raw MTLStorageMode numbering -- that would
                                       # be Shared=0/Private=2/Memoryless=3). Only two values
                                       # confirmed; Private/Managed untested, don't assume a number.


def records(data):
    """Yield (offset, len, selector, kind, sig, payload) for each record."""
    off, n = 8, len(data)
    while off + MIN_RECORD_LEN <= n:
        (ln,) = struct.unpack_from('<I', data, off)
        if ln < MIN_RECORD_LEN or ln > MAX_RECORD_LEN or off + ln > n:
            off += 4
            continue
        record_end = off + ln
        sel = struct.unpack_from('<i', data, off + 4)[0]
        kind = struct.unpack_from('<I', data, off + 32)[0]
        sig_start = off + RECORD_FIXED_PREFIX
        sig_end = data.find(b'\0', sig_start, record_end)
        if sig_end < 0:
            off = record_end
            continue
        sig_len = sig_end - sig_start
        payload_start = sig_start + ((sig_len + 1 + 3) // 4) * 4
        if payload_start > record_end:
            off = record_end
            continue
        sig = data[sig_start:sig_end].decode('ascii', 'replace')
        payload = data[payload_start:record_end]
        yield off, ln, sel, kind, sig, payload
        off = record_end


def parse_args(sig, payload):
    out, p = [], 0
    for c in sig:
        try:
            if c == 'C':
                out.append(struct.unpack_from('<Q', payload, p)[0]); p += 8
            elif c == 'S':
                e = payload.find(b'\0', p)
                if e < 0:
                    break
                out.append(payload[p:e].decode('utf-8', 'replace')); p = e + 1
            elif c in 'ui':
                out.append(struct.unpack_from('<I', payload, p)[0]); p += 4
            elif c in 'lw':
                out.append(struct.unpack_from('<Q', payload, p)[0]); p += 8
            elif c == 'b':
                out.append(payload[p]); p += 1
            else:
                break
        except Exception:
            break
    return out


def device_resources(trace):
    hits = glob.glob(os.path.join(trace, 'device-resources-*'))
    if not hits:
        raise SystemExit('no device-resources-* in %s' % trace)
    with open(hits[0], 'rb') as stream:
        return stream.read()


def inventory(trace):
    """label -> list of {file, width, height, bytes_per_row, slice}"""
    data = device_resources(trace)
    labels, dumps = {}, []
    for _o, _l, sel, _k, sig, pl in records(data):
        u = sel & 0xffffffff
        if u in (SEL_SET_LABEL, SEL_BUF_LABEL) and sig == 'CS':
            args = parse_args(sig, pl)
            if len(args) < 2:
                continue
            ptr, label = args
            labels[ptr] = label
        elif u == SEL_DUMP:
            m = re.search(rb'MTLTexture-[0-9A-Za-z\-]+', pl)
            if not m:
                continue
            ptr = struct.unpack_from('<Q', pl, 0)[0]
            head = pl[8:m.start()]
            ints = struct.unpack_from('<%dI' % (len(head) // 4), head, 0)
            tail = pl[m.end():]
            tints = struct.unpack_from('<%dI' % (len(tail) // 4), tail, 0)
            nz = [v for v in ints if v]
            w, h = (nz[0], nz[1]) if len(nz) > 1 else (0, 0)
            dumps.append((ptr, m.group(0).decode(), w, h))
    inv = {}
    for ptr, name, w, h in dumps:
        inv.setdefault(labels.get(ptr, '<unlabeled %#x>' % ptr), []).append(
            dict(file=name, width=w, height=h, bytes_per_pixel=_bpp(trace, name, w, h),
                 slice=int(name.rsplit('slice', 1)[-1]) if 'slice' in name else 0))
    return inv


def _bpp(trace, name, w, h):
    """Bytes per pixel, resolved from the dump's own size.

    4 = color, 5 = depth32float+stencil8 stored as two planes. The capture header is
    8192 or 16384 depending on format, so probe rather than assume either.
    """
    path = os.path.join(trace, name)
    if not (w and h and os.path.exists(path)):
        return 0
    size = os.path.getsize(path)
    for bpp in (4, 5):
        if size - w * h * bpp in (8192, 16384):
            return bpp
    return 4


def load_texture(trace, entry, planar_depth=None):
    """4-byte formats -> (h,w,4) uint8; depth/stencil -> (depth float32, stencil uint8)."""
    import numpy as np
    path = os.path.join(trace, entry['file'])
    w, h = entry['width'], entry['height']
    bpp = entry['bytes_per_pixel']
    size = os.path.getsize(path)
    is_ds = planar_depth if planar_depth is not None else (bpp == 5)
    if is_ds:
        off = size - (w * h * 5)
        z = np.fromfile(path, dtype=np.float32, offset=off, count=w * h).reshape(h, w)
        s = np.fromfile(path, dtype=np.uint8, offset=off + w * h * 4,
                        count=w * h).reshape(h, w)
        return z, s
    off = size - h * w * 4
    return np.fromfile(path, dtype=np.uint8, offset=off,
                       count=h * w * 4).reshape(h, w, 4)


def cmd_descriptors(trace):
    """Per-texture creation-descriptor fields confirmed against Xcode ground truth.

    Only prints fields with a verified decode (allocated size, storage mode). Labels
    without a creation-descriptor cluster (e.g. externally-owned swapchain textures like
    Color_SwapChain0/Depth_SwapChain0 -- confirmed absent from this record family, not a
    parsing miss) are silently skipped.
    """
    data = device_resources(trace)
    labels, alloc_size, storage_mode = {}, {}, {}
    STORAGE_NAMES = {1: 'Shared', 2: 'Memoryless'}  # only these two confirmed so far
    for _o, _l, sel, _k, sig, pl in records(data):
        u = sel & 0xffffffff
        if u == SEL_SET_LABEL and sig == 'CS':
            args = parse_args(sig, pl)
            if len(args) < 2:
                continue
            ptr, label = args
            labels[ptr] = label
        elif u == SEL_TEX_ALLOCATED_SIZE and sig == 'Cui':
            ptr, val = parse_args(sig, pl)
            alloc_size[ptr] = val
        elif u == SEL_TEX_STORAGE_MODE and sig == 'Cui':
            ptr, val = parse_args(sig, pl)
            storage_mode[ptr] = val
    ptrs = set(alloc_size) & set(storage_mode)
    for ptr in sorted(ptrs, key=lambda p: labels.get(p, '')):
        label = labels.get(ptr, '<unlabeled %#x>' % ptr)
        mode = storage_mode[ptr]
        mode_str = STORAGE_NAMES.get(mode, 'unknown(%d)' % mode)
        print('%-45s allocated=%-10d storageMode=%s' % (label, alloc_size[ptr], mode_str))


def cmd_textures(trace):
    for label, entries in sorted(inventory(trace).items()):
        e = entries[0]
        kind = 'depth32f+s8 (planar)' if e['bytes_per_pixel'] == 5 else 'color 4B'
        print('%-52s %5dx%-5d slices=%-3d %s' % (
            label, e['width'], e['height'], len(entries), kind))


def cmd_encoders(trace):
    with open(os.path.join(trace, 'capture'), 'rb') as stream:
        data = stream.read()
    for _o, _l, sel, _k, sig, pl in records(data):
        u = sel & 0xffffffff
        if sig != 'CS':
            continue
        args = parse_args(sig, pl)
        if len(args) < 2:
            continue
        s = args[1]
        if u == SEL_ENC_LABEL:
            print('\n' + s)
        elif u in (SEL_DEBUG_GROUP, SEL_SCOPE):
            print('   ' + s)


def cmd_dump(trace, label, out):
    import numpy as np
    from PIL import Image
    inv = inventory(trace)
    entries = inv.get(label) or next(
        (v for k, v in inv.items() if label.lower() in k.lower()), None)
    if not entries:
        raise SystemExit('no texture matching %r' % label)
    tiles = []
    for e in sorted(entries, key=lambda x: x['slice']):
        a = load_texture(trace, e)
        if isinstance(a, tuple):
            z = a[0]
            img = ((z - z.min()) / (np.ptp(z) + 1e-12) * 255).astype(np.uint8)
            img = np.stack([img] * 3, -1)
        else:
            img = np.ascontiguousarray(a[:, :, [2, 1, 0]])
        tiles.append(np.array(Image.fromarray(img).resize((944, 896), Image.LANCZOS)))
    sep = np.full((6, 944, 3), 128, np.uint8)
    grid = tiles[0]
    for t in tiles[1:]:
        grid = np.concatenate([grid, sep, t], axis=0)
    Image.fromarray(grid).save(out)
    print('wrote %s  (%d slice(s) stacked top-to-bottom)' % (out, len(tiles)))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    trace, cmd = sys.argv[1], sys.argv[2]
    if cmd == 'textures':
        cmd_textures(trace)
    elif cmd == 'encoders':
        cmd_encoders(trace)
    elif cmd == 'dump':
        cmd_dump(trace, sys.argv[3], sys.argv[4])
    elif cmd == 'descriptors':
        cmd_descriptors(trace)
    elif cmd == 'records':
        data = open(os.path.join(trace, sys.argv[3]), 'rb').read()
        filt = sys.argv[4].lower() if len(sys.argv) > 4 else None
        for off, ln, sel, kind, sig, pl in records(data):
            line = ('%9d len=%5d sel=%#010x kind=%3d sig=%-22r ' % (
                off, ln, sel & 0xffffffff, kind, sig)) + ' '.join(map(repr, parse_args(sig, pl)))
            if filt is None or filt in line.lower():
                print(line)
    else:
        raise SystemExit(__doc__)
