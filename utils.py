from lib.common import *
from lib.keys import NTR, TWL, CTR
from lib.ctr_cia import CIAReader, CIABuilder
from lib.ctr_cci import CCIReader, CCIBuilder
from lib.ctr_ncch import NCCHReader, NCCHBuilder
from lib.ctr_exefs import ExeFSReader, ExeFSBuilder
from lib.ctr_romfs import RomFSReader, RomFSBuilder
from lib.ctr_crr import crrReader
from lib.ctr_tmd import TMDReader, TMDBuilder
from lib.ctr_tik import tikReader, tikBuilder
from lib.ctr_cdn import CDNReader, CDNBuilder
from lib.ctr_cnt import cntReader
from lib.ntr_twl_srl import SRLReader, get_rsa_key_idx
import hashlib
import logging
import shutil

logger = logging.getLogger(__name__)

def srl_retail2dev(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_dev.srl'
    
    srl = SRLReader(path, dev=0)
    shutil.copyfile(path, 'tmp.nds')

    if srl.media == 'Game card' and srl.secure_area_status == 'decrypted': # Encrypt NTR secure area for decrypted game card SRLs
        with open(path, 'rb') as f:
            f.seek(0x4000)
            secure_area = f.read(2048)
            secure_area_enc = srl.encrypt_secure_area(secure_area, NTR.blowfish_key)
        with open('tmp.nds', 'r+b') as f:
            f.seek(0x4000)
            f.write(secure_area_enc)

    if srl.modcrypted: # Decrypt modcrypt regions and re-encrypt with dev key
        srl.decrypt_modcrypt()
        f = open('decrypted.nds', 'rb')
        key = bytes(srl.hdr)[:16][::-1]
        for i in srl.modcrypt:
            g = open('tmp.nds', 'r+b')
            f.seek(i['offset'])
            g.seek(i['offset'])

            counter = Counter.new(128, initial_value=readbe(i['counter']))
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            for data in read_chunks(f, i['size']):
                g.write(TWL.aes_ctr(cipher, data))
            g.close()
        f.close()
        os.remove('decrypted.nds')
    
    if srl.hdr.unit_code == 2 or srl.hdr.unit_code == 3 or (srl.hdr.unit_code == 0 and srl.hdr_ext.flags != 0): # Set DeveloperApp flag
        srl.hdr_ext.flags |= (1 << 7)
        with open('tmp.nds', 'r+b') as f:
            f.seek(0x1BF)
            f.write(int8tobytes(srl.hdr_ext.flags))
    
    if not (srl.hdr.unit_code == 0 and readbe(srl.hdr_ext.sig) == 0): # Re-generate header signature
        idx = get_rsa_key_idx(srl.hdr, srl.hdr_ext)
        n = TWL.rsa_key_mod[idx]
        d = TWL.rsa_key_priv[idx]
        
        f = open('tmp.nds', 'rb')
        sha1_calculated = Crypto.sha1(f, 0xE00)
        f.close()
        sha1_padded = b'\x00\x01' + b'\xff' * 105 + b'\x00' + sha1_calculated
        enc = pow(readbe(sha1_padded), readbe(d[1]), readbe(n[1])).to_bytes(0x80, 'big')
        with open('tmp.nds', 'r+b') as f:
            f.seek(0xF80)
            f.write(enc)

    if srl.media == 'Game card': # Re-generate undumpable area i.e. KeyTables for game card SRLs
        srl = SRLReader('tmp.nds', dev=1)
        srl.regen_undumpable()
        os.remove('tmp.nds')
        shutil.move('new.nds', out)
    else:
        shutil.move('tmp.nds', out)

def cia_dev2retail(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_retail.cia'
    
    cia = CIAReader(path, dev=1)
    cia.extract()

    cf = list(cia.files.keys())
    cf.remove('cia_header.bin')
    cf.remove('cert.bin')
    cf.remove('tik')
    cf.remove('tmd')
    if 'meta.bin' in cf:
        meta = 1
        cf.remove('meta.bin')
    else:
        meta = 0

    for i in cf:
        if i.endswith('.ncch'):
            ncch = NCCHReader(i, dev=1)
            ncch.extract() # NOTE: no need to resign CRR since CRR body sig will pass (all that matters)
            ncch_header = 'ncch_header.bin'
            if os.path.isfile('exheader.bin'):
                exheader = 'exheader.bin'
            else:
                exheader = ''
            if os.path.isfile('logo.bin'):
                logo = 'logo.bin'
            else:
                logo = ''
            if os.path.isfile('plain.bin'):
                plain = 'plain.bin'
            else:
                plain = ''
            if os.path.isfile('exefs.bin'):
                exefs = 'exefs.bin'
            else:
                exefs = ''
            if os.path.isfile('romfs.bin'):
                romfs = 'romfs.bin'
            else:
                romfs = ''
            os.remove(i)
            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='Secure1', regen_sig='retail', dev=0, out=i)
            for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
                if j != '':
                    os.remove(j)

    tmd = TMDReader('tmd', dev=1)
    TMDBuilder(content_files=cf, content_files_dev=0, titleID=tmd.titleID, title_ver=tmd.hdr.title_ver, save_data_size=tmd.hdr.save_data_size, priv_save_data_size=tmd.hdr.priv_save_data_size, twl_flag=tmd.hdr.twl_flag, crypt=0, regen_sig='retail')
    os.remove('tmd')

    tik = tikReader('tik', dev=1)
    tikBuilder(tik='tik', titlekey=hex(readbe(tik.titlekey))[2:].zfill(32), regen_sig='retail') # Use original (decrypted) titlekey
    os.remove('tik')

    CIABuilder(content_files=cf, tik='tik_new', tmd='tmd_new', meta=meta, dev=0, out=out)
    
    for i in cf + ['tmd_new', 'tik_new', 'cia_header.bin', 'cert.bin', 'meta.bin']:
        if os.path.isfile(i):
            os.remove(i)

def cia_retail2dev(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_dev.cia'
    
    cia = CIAReader(path, dev=0)
    cia.extract()

    cf = list(cia.files.keys())
    cf.remove('cia_header.bin')
    cf.remove('cert.bin')
    cf.remove('tik')
    cf.remove('tmd')
    if 'meta.bin' in cf:
        meta = 1
        cf.remove('meta.bin')
    else:
        meta = 0

    for i in cf:
        if i.endswith('.ncch'):
            ncch = NCCHReader(i, dev=0)
            ncch.extract()
            ncch_header = 'ncch_header.bin'
            if os.path.isfile('exheader.bin'):
                exheader = 'exheader.bin'
            else:
                exheader = ''
            if os.path.isfile('logo.bin'):
                logo = 'logo.bin'
            else:
                logo = ''
            if os.path.isfile('plain.bin'):
                plain = 'plain.bin'
            else:
                plain = ''
            if os.path.isfile('exefs.bin'):
                exefs = 'exefs.bin'
            else:
                exefs = ''
            if os.path.isfile('romfs.bin'):
                romfs = 'romfs.bin'
                romfs_rdr = RomFSReader('romfs.bin')
                if '.crr/static.crr' in romfs_rdr.files.keys() or '.crr\\static.crr' in romfs_rdr.files.keys():
                    romfs_rdr.extract()
                    crr = crrReader('romfs/.crr/static.crr')
                    crr.regen_sig(dev=1)
                    os.remove('romfs.bin')
                    RomFSBuilder(romfs_dir='romfs/', out='romfs.bin')
                    shutil.rmtree('romfs/')
            else:
                romfs = ''
            os.remove(i)
            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='Secure1', regen_sig='dev', dev=1, out=i)
            for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
                if j != '':
                    os.remove(j)

    tmd = TMDReader('tmd', dev=0)
    TMDBuilder(content_files=cf, content_files_dev=1, titleID=tmd.titleID, title_ver=tmd.hdr.title_ver, save_data_size=tmd.hdr.save_data_size, priv_save_data_size=tmd.hdr.priv_save_data_size, twl_flag=tmd.hdr.twl_flag, crypt=1, regen_sig='dev')
    os.remove('tmd')

    tik = tikReader('tik', dev=0)
    tikBuilder(tik='tik', titlekey=hex(readbe(tik.titlekey))[2:].zfill(32), regen_sig='dev') # Use original (decrypted) titlekey
    os.remove('tik')

    CIABuilder(content_files=cf, tik='tik_new', tmd='tmd_new', meta=meta, dev=1, out=out)
    
    for i in cf + ['tmd_new', 'tik_new', 'cia_header.bin', 'cert.bin', 'meta.bin']:
        if os.path.isfile(i):
            os.remove(i)

def cci_dev2retail(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_retail.3ds'

    cci = CCIReader(path, dev=1)
    cci.extract()

    parts = list(cci.files.keys())
    parts.remove('cci_header.bin')
    parts.remove('card_info.bin')
    parts.remove('mastering_info.bin')
    parts.remove('initialdata.bin')
    if 'card_device_info.bin' in parts:
        parts.remove('card_device_info.bin')

    for i in parts:
        if i.endswith('.ncch'):
            ncch = NCCHReader(i, dev=1)
            ncch.extract() # NOTE: no need to resign CRR since CRR body sig will pass (all that matters)
            ncch_header = 'ncch_header.bin'
            if os.path.isfile('exheader.bin'):
                exheader = 'exheader.bin'
            else:
                exheader = ''
            if os.path.isfile('logo.bin'):
                logo = 'logo.bin'
            else:
                logo = ''
            if os.path.isfile('plain.bin'):
                plain = 'plain.bin'
            else:
                plain = ''
            if os.path.isfile('exefs.bin'):
                exefs = 'exefs.bin'
            else:
                exefs = ''
            if os.path.isfile('romfs.bin'):
                romfs = 'romfs.bin'
            else:
                romfs = ''
            os.remove(i)
            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='Secure1', regen_sig='retail', dev=0, out=i)
            for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
                if j != '':
                    os.remove(j)

    CCIBuilder(cci_header='cci_header.bin', card_info='card_info.bin', mastering_info='mastering_info.bin', initialdata='', card_device_info='', ncchs=parts, cardbus_crypto='Secure0', regen_sig='retail', dev=0, gen_card_device_info=0, out=out)
    
    for i in parts + ['cci_header.bin', 'card_info.bin', 'mastering_info.bin', 'initialdata.bin', 'card_device_info.bin']:
        if os.path.isfile(i):
            os.remove(i)

def cci_retail2dev(path, out=''):
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_dev.3ds'

    cci = CCIReader(path, dev=0)
    cci.extract()

    parts = list(cci.files.keys())
    parts.remove('cci_header.bin')
    parts.remove('card_info.bin')
    parts.remove('mastering_info.bin')
    parts.remove('initialdata.bin')
    if 'card_device_info.bin' in parts:
        parts.remove('card_device_info.bin')

    for i in parts:
        if i.endswith('.ncch'):
            ncch = NCCHReader(i, dev=0)
            ncch.extract()
            ncch_header = 'ncch_header.bin'
            if os.path.isfile('exheader.bin'):
                exheader = 'exheader.bin'
            else:
                exheader = ''
            if os.path.isfile('logo.bin'):
                logo = 'logo.bin'
            else:
                logo = ''
            if os.path.isfile('plain.bin'):
                plain = 'plain.bin'
            else:
                plain = ''
            if os.path.isfile('exefs.bin'):
                exefs = 'exefs.bin'
            else:
                exefs = ''
            if os.path.isfile('romfs.bin'):
                romfs = 'romfs.bin'
                romfs_rdr = RomFSReader('romfs.bin')
                if '.crr/static.crr' in romfs_rdr.files.keys() or '.crr\\static.crr' in romfs_rdr.files.keys():
                    romfs_rdr.extract()
                    crr = crrReader('romfs/.crr/static.crr')
                    crr.regen_sig(dev=1)
                    os.remove('romfs.bin')
                    RomFSBuilder(romfs_dir='romfs/', out='romfs.bin')
                    shutil.rmtree('romfs/')
            else:
                romfs = ''
            os.remove(i)
            NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, crypto='Secure1', regen_sig='dev', dev=1, out=i)
            for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
                if j != '':
                    os.remove(j)

    CCIBuilder(cci_header='cci_header.bin', card_info='card_info.bin', mastering_info='mastering_info.bin', initialdata='', card_device_info='', ncchs=parts, cardbus_crypto='fixed', regen_sig='dev', dev=1, gen_card_device_info=1, out=out)
    
    for i in parts + ['cci_header.bin', 'card_info.bin', 'mastering_info.bin', 'initialdata.bin', 'card_device_info.bin']:
        if os.path.isfile(i):
            os.remove(i)

def ncch_extractall(path, dev=0):
    name = os.path.splitext(os.path.basename(path))[0]
    if not os.path.exists(name):
        os.mkdir(name)

    ncch = NCCHReader(path, dev)
    ncch.extract()
    exefs_code_compress = 0
    for i in ['ncch_header.bin', 'exheader.bin', 'logo.bin', 'plain.bin', 'exefs.bin', 'romfs.bin']:
        if os.path.isfile(i):
            if i == 'exheader.bin':
                with open(i, 'rb') as f:
                    f.seek(0xD)
                    flag = readle(f.read(1))
                    if flag & 1:
                        exefs_code_compress = 1

            shutil.move(i, os.path.join(name, i))
    
    os.chdir(name)
    # Extract ExeFS
    if os.path.isfile('exefs.bin'):
        exefs = ExeFSReader('exefs.bin')
        exefs.extract(code_compressed=exefs_code_compress)
        if not os.path.exists('exefs'):
            os.mkdir('exefs')
        for i in exefs.files.keys():
            shutil.move(i, os.path.join('exefs', i))
        if exefs_code_compress:
            os.remove(os.path.join('exefs', '.code.bin'))
            shutil.move('code-decompressed.bin', os.path.join('exefs', '.code.bin'))
    
    # Extract RomFS
    if os.path.isfile('romfs.bin'):
        romfs = RomFSReader('romfs.bin')
        romfs.extract()
    
    os.chdir('..')

def macos_clean(path):
    proc = subprocess.call(['dot_clean', path], stdout=None, stderr=None)
    proc = subprocess.call(['find', path, '-type', 'f', '-name', '.DS_Store', '-exec', 'rm', '{}', ';'], stdout=None, stderr=None)

def ncch_rebuildall(path, dev=0):
    os.chdir(path)
    name = os.path.basename(os.getcwd())
    out = f'{name}.ncch'

    if os.path.isdir('exefs/'):
        if platform.system() == 'Darwin':
            macos_clean('exefs/')
        if os.path.isfile('exefs.bin'):
            os.remove('exefs.bin')

        exefs_code_compress = 0
        if os.path.isfile('exheader.bin'):
            with open('exheader.bin', 'rb') as f:
                f.seek(0xD)
                flag = readle(f.read(1))
                if flag & 1:
                    exefs_code_compress = 1

        ExeFSBuilder(exefs_dir='exefs/', code_compress=exefs_code_compress)
    
    if os.path.isdir('romfs/'):
        if platform.system() == 'Darwin':
            macos_clean('romfs/')
        if os.path.isfile('romfs.bin'):
            os.remove('romfs.bin')
        RomFSBuilder(romfs_dir='romfs/')
    
    ncch_header = 'ncch_header.bin'
    if os.path.isfile('exheader.bin'):
        exheader = 'exheader.bin'
    else:
        exheader = ''
    if os.path.isfile('logo.bin'):
        logo = 'logo.bin'
    else:
        logo = ''
    if os.path.isfile('plain.bin'):
        plain = 'plain.bin'
    else:
        plain = ''
    if os.path.isfile('exefs.bin'):
        exefs = 'exefs.bin'
    else:
        exefs = ''
    if os.path.isfile('romfs.bin'):
        romfs = 'romfs.bin'
    else:
        romfs = ''
    NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, dev=dev, out=out)
    if not os.path.isfile(f'../{out}'):
        shutil.move(out, f'../{out}')
    else:
        shutil.move(out, f'../{name} (new).ncch')
    os.chdir('..')

def cci_extractall(path, dev=0):
    name = os.path.splitext(os.path.basename(path))[0]
    if not os.path.exists(name):
        os.mkdir(name)

    cci = CCIReader(path, dev)
    cci.extract()

    for i in cci.files.keys():
        shutil.move(i, os.path.join(name, i))

        if i.endswith('.ncch'):
            os.chdir(name)
            ncch_extractall(i)
            os.chdir('..')

def cci_rebuildall(path, dev=0):
    os.chdir(path)
    name = os.path.basename(os.getcwd())
    out = f'{name}.3ds'

    ncchs = []
    card_device_info = ''
    if os.path.isfile('card_device_info.bin'):
        card_device_info = 'card_device_info.bin'
    
    for i in os.listdir('.'):
        if os.path.isdir(i):
            ncchs.append(f'{i}.ncch')
            if os.path.isfile(f'{i}.ncch'):
                os.remove(f'{i}.ncch')
            ncch_rebuildall(i, dev)
    
    CCIBuilder(cci_header='cci_header.bin', card_info='card_info.bin', mastering_info='mastering_info.bin', initialdata='initialdata.bin', card_device_info=card_device_info, ncchs=ncchs, dev=dev, out=out)
    if not os.path.isfile(f'../{out}'):
        shutil.move(out, f'../{out}')
    else:
        shutil.move(out, f'../{name} (new).3ds')
    os.chdir('..')

def cia_extractall(path, dev=0):
    name = os.path.splitext(os.path.basename(path))[0]
    if not os.path.exists(name):
        os.mkdir(name)

    cia = CIAReader(path, dev)
    cia.extract()

    for i in cia.files.keys():
        shutil.move(i, os.path.join(name, i))

        if i.endswith('.ncch'):
            os.chdir(name)
            ncch_extractall(i)
            os.chdir('..')

def cia_rebuildall(path, dev=0):
    os.chdir(path)
    name = os.path.basename(os.getcwd())
    out = f'{name}.cia'

    cf = []
    meta = 0
    if os.path.isfile('meta.bin'):
        meta = 1

    for i in os.listdir('.'):
        if os.path.isdir(i) or (os.path.isfile(i) and i.endswith('.nds')):
            if os.path.isdir(i):
                cf.append(f'{i}.ncch')
                if os.path.isfile(f'{i}.ncch'):
                    os.remove(f'{i}.ncch')
                ncch_rebuildall(i, dev)
            else:
                cf.append(i)

    CIABuilder(certs='cert.bin', content_files=cf, tik='tik', tmd='tmd', meta=meta, dev=dev, out=out)
    if not os.path.isfile(f'../{out}'):
        shutil.move(out, f'../{out}')
    else:
        shutil.move(out, f'../{name} (new).cia')
    os.chdir('..')

def cci2cia(path, out='', cci_dev=0, cia_dev=0):
    """Convert CCI (3DS cartridge) to CIA format."""
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = f'{name}_conv.cia'

    cci = CCIReader(path, cci_dev)
    cci.extract()

    ncchs = [i for i in cci.files.keys() if i.endswith('.ncch')]
    for i in ['content6.update_n3ds.ncch', 'content7.update_o3ds.ncch']:
        if i in ncchs:
            ncchs.remove(i)
            os.remove(i)

    if cia_dev == 0:
        regen_sig = 'retail'
    else:
        regen_sig = 'dev'

    for i in ncchs:
        n = NCCHReader(i, dev=cci_dev)
        n.extract()
        os.remove(i)
        
        if i.startswith('content0'):
            with open('exheader.bin', 'r+b') as f:
                f.seek(0xD)
                flag = readle(f.read(1))
                f.seek(0xD)
                f.write(int8tobytes(flag | 2)) # Set SDApplication bit

        ncch_header = 'ncch_header.bin'
        if os.path.isfile('exheader.bin'):
            exheader = 'exheader.bin'
        else:
            exheader = ''
        if os.path.isfile('logo.bin'):
            logo = 'logo.bin'
        else:
            logo = ''
        if os.path.isfile('plain.bin'):
            plain = 'plain.bin'
        else:
            plain = ''
        if os.path.isfile('exefs.bin'):
            exefs = 'exefs.bin'
        else:
            exefs = ''
        if os.path.isfile('romfs.bin'):
            romfs = 'romfs.bin'
        else:
            romfs = ''
        NCCHBuilder(ncch_header=ncch_header, exheader=exheader, logo=logo, plain=plain, exefs=exefs, romfs=romfs, regen_sig=regen_sig, dev=cia_dev, out=i)
        for j in [ncch_header, exheader, logo, plain, exefs, romfs]:
            if j != '':
                os.remove(j)
    
    cf = []
    d = {
        'content0.game.ncch': '0000.00000000.ncch',
        'content1.manual.ncch': '0001.00000001.ncch',
        'content2.dlp.ncch': '0002.00000002.ncch'
    }
    for i in ncchs:
        cf.append(d[i])
        shutil.move(i, d[i])

    TMDBuilder(content_files=cf, content_files_dev=cia_dev, titleID=hex(readle(cci.hdr.mediaID))[2:].zfill(16), title_ver=0, crypt=0, regen_sig=regen_sig, out='tmd')
    tikBuilder(titleID=hex(readle(cci.hdr.mediaID))[2:].zfill(16), title_ver=0, regen_sig=regen_sig, out='tik')

    CIABuilder(content_files=cf, tik='tik', tmd='tmd', meta=1, dev=cia_dev, out=out)
    
    for i in ['cci_header.bin', 'card_info.bin', 'mastering_info.bin', 'initialdata.bin', 'card_device_info.bin'] + cf:
        if os.path.exists(i):
            os.remove(i)



def cdn2cia(path, out='', title_ver='', cdn_dev=0, cia_dev=0, decrypt=0):
    """
    Convert CDN to CIA format.
    
    Args:
        path: Path to CDN directory
        out: Output CIA filename (auto-generated if empty)
        title_ver: Specific title version to use (latest if empty)
        cdn_dev: Whether CDN files are dev-encrypted (0=retail, 1=dev)
        cia_dev: Whether output CIA should be dev-signed (0=retail, 1=dev)
        decrypt: Whether to decrypt NCCH content (0=keep encrypted, 1=decrypt)
    """
    # Always use reversible decryption for decrypted CIAs
    if decrypt:
        return cdn2cia_reversible_decrypt(path, out, title_ver, cdn_dev, cia_dev)
    
    # Standard encrypted CIA conversion
    os.chdir(path)
    name = os.path.basename(os.getcwd())

    content_files = []
    tmds = []
    tmd = ''
    tik = ''
    for i in os.listdir('.'):
        if i.startswith('tmd.') or i == 'tmd':
            tmds.append(i)
        elif i == 'cetk':
            tik = i
        elif i.startswith('0'):
            content_files.append(i)
    
    if len(tmds) == 1:
        tmd = tmds[0]
    else:
        tmds.sort(key=lambda h: int(os.path.splitext(h)[1].strip('.') or 0))
        if title_ver == '':
            tmd = tmds[-1]
        else:
            tmd = f'tmd.{title_ver}'
    
    if cia_dev == 0:
        regen_sig = 'retail'
    else:
        regen_sig = 'dev'

    t = TMDReader(tmd)
    if out == '':
        out = f'{name}.{t.hdr.title_ver}.cia'
    
    cdn = CDNReader(content_files=content_files, tmd=tmd, tik=tik, dev=cdn_dev)
    cdn.extract()
    cf = [i for i in os.listdir('.') if i.endswith('.ncch') or i.endswith('.nds')]
    
    tmd += '.extracted'

    if tik == '':
        tikBuilder(titleID=t.titleID, title_ver=t.hdr.title_ver, titlekey=hex(readbe(cdn.titlekey))[2:].zfill(32), regen_sig=regen_sig, out='tik')
        tik = 'tik'
    else:
        tik += '.extracted'

    meta = 1
    if t.titleID[3:5] == '48':
        meta = 0
    
    CIABuilder(content_files=cf, tik=tik, tmd=tmd, meta=meta, dev=cia_dev, out='tmp.cia')
    
    for i in cf + [tik, tmd]:
        if os.path.isfile(i):
            os.remove(i)

    shutil.move('tmp.cia', '../tmp.cia')
    os.chdir('..')
    shutil.move('tmp.cia', out)
    print(f'Converted CDN to CIA: {out}')

def cia2cdn(path, out='', titlekey='', cia_dev=0, auto_detect=True):
    """
    Convert CIA to CDN format with auto-detection of encryption state.
    
    Args:
        path: Path to CIA file
        out: Output directory name (auto-generated if empty)
        titlekey: Optional titlekey override (hex string)
        cia_dev: Whether CIA uses dev crypto (0=retail, 1=dev)
        auto_detect: Whether to auto-detect if CIA needs re-encryption for CDN
    """
    if auto_detect:
        # Check if this is a reversible decrypted CIA that needs re-encryption
        cia = CIAReader(path, cia_dev)
        cia.extract()
        
        # Check TMD to see if content is marked as decrypted
        tmd_reader = TMDReader('tmd', cia_dev)
        is_decrypted_content = False
        
        # Check if any content chunks have decrypted flags
        for chunk in tmd_reader.content_chunks:
            if (chunk.content_type & 1) == 0:  # Missing encryption flag
                is_decrypted_content = True
                break
        
        # Clean up extracted files
        for cleanup_file in ['cia_header.bin', 'cert.bin', 'tmd', 'tik', 'meta.bin']:
            if os.path.isfile(cleanup_file):
                os.remove(cleanup_file)
        
        cf_temp = [i for i in os.listdir('.') if i.endswith('.ncch') or i.endswith('.nds')]
        for temp_file in cf_temp:
            if os.path.isfile(temp_file):
                os.remove(temp_file)
        
        if is_decrypted_content:
            # This appears to be a reversible decrypted CIA - use the enhanced function
            return cia2cdn_encrypted(path, out, cia_dev, titlekey)
    
    # Use original logic for standard encrypted CIAs
    name = os.path.splitext(os.path.basename(path))[0]
    if out == '':
        out = name

    cia = CIAReader(path, cia_dev)
    cia.extract()
    for i in ['cia_header.bin', 'cert.bin', 'meta.bin']:
        if os.path.isfile(i):
            os.remove(i)
    
    tik = 'tik'
    tik_read = tikReader(tik)
    if not tik_read.verify()[0][1]: # Ticket has invalid sig
        tik = ''
    
    cf = [i for i in os.listdir('.') if i.endswith('.ncch') or i.endswith('.nds')]
    CDNBuilder(content_files=cf, tik=tik, tmd='tmd', titlekey=titlekey, out=out)

    for i in ['tik', 'tmd'] + cf:
        if os.path.isfile(i):
            os.remove(i)

def csu2retailcias(path, out=''):
    if out == '':
        out = 'updates_retail/'

    cci = CCIReader(path, dev=1)
    cci.extract()

    n = NCCHReader('content0.game.ncch', dev=1)
    n.extract()
    romfs = RomFSReader('romfs.bin')
    romfs.extract()

    cnt = cntReader('romfs/contents/Contents.cnt', 'romfs/contents/CupList')
    cnt.extract()

    for i in ['cci_header.bin', 'card_info.bin', 'mastering_info.bin', 'initialdata.bin', 'card_device_info.bin', 'content0.game.ncch', 'ncch_header.bin', 'exheader.bin', 'logo.bin', 'plain.bin', 'exefs.bin', 'romfs.bin']:
        if os.path.exists(i):
            os.remove(i)
    shutil.rmtree('romfs/')

    if not os.path.isdir(out):
        os.mkdir(out)
    for i in os.listdir('updates/'):
        cia_dev2retail(path=os.path.join('updates/', i), out=os.path.join(out, i))
    shutil.rmtree('updates/')

def cdn2cia_reversible_decrypt(path, out='', title_ver='', cdn_dev=0, cia_dev=0):
    """
    Convert CDN to decrypted CIA with maximum reversibility.
    
    This function:
    - Uses NCCHReader.decrypt() for minimal flag changes (only NoCrypto flag)
    - Uses TMDBuilderPreserveSignature to preserve original TMD signature
    - Sets proper TMD content flags for decrypted content
    - Matches GodMode9's approach for maximum compatibility
    
    Args:
        path: Path to CDN directory
        out: Output CIA filename (auto-generated if empty)
        title_ver: Specific title version to use (latest if empty)
        cdn_dev: Whether CDN is dev (1) or retail (0)
        cia_dev: Whether output CIA should be dev (1) or retail (0)
    """
    os.chdir(path)
    name = os.path.basename(os.getcwd())

    content_files = []
    tmds = []
    tmd = ''
    tik = ''
    for i in os.listdir('.'):
        if i.startswith('tmd.') or i == 'tmd':
            tmds.append(i)
        elif i == 'cetk':
            tik = i
        elif i.startswith('0'):
            content_files.append(i)
    
    if len(tmds) == 1:
        tmd = tmds[0]
    else:
        tmds.sort(key=lambda h: int(os.path.splitext(h)[1].strip('.') or 0))
        if title_ver == '':
            tmd = tmds[-1]
        else:
            tmd = f'tmd.{title_ver}'
    
    if cia_dev == 0:
        regen_sig = 'retail'
    else:
        regen_sig = 'dev'

    t = TMDReader(tmd)
    if out == '':
        out = f'{name}.{t.hdr.title_ver}.decrypted.cia'
    
    logger.info(f'Creating reversible decrypted CIA: {out}')
    
    # Extract CDN content files
    cdn = CDNReader(content_files=content_files, tmd=tmd, tik=tik, dev=cdn_dev)
    cdn.extract()
    cf = [i for i in os.listdir('.') if i.endswith('.ncch') or i.endswith('.nds')]
    logger.debug(f'Extracted content files: {cf}')
    
    # Decrypt NCCHs using NCCHReader.decrypt() for minimal flag changes
    for ncch_file in cf:
        if ncch_file.endswith('.ncch'):
            logger.debug(f'Processing {ncch_file}, size: {os.path.getsize(ncch_file)} bytes')
            
            # Verify the file is a valid NCCH
            with open(ncch_file, 'rb') as f:
                f.seek(0x100)
                magic = f.read(4)
                if magic != b'NCCH':
                    logger.warning(f'{ncch_file} does not appear to be a valid NCCH file (magic: {magic})')
                    continue
                
                # Check current encryption status
                f.seek(0x18F)  # flags[7]
                flags = f.read(1)
                is_decrypted = flags[0] & 0x4 if len(flags) > 0 else False
                uses_seed = flags[0] & 0x20 if len(flags) > 0 else False
                
                logger.debug(f'{ncch_file} - flags[7]: 0x{flags[0]:02x}')
                logger.debug(f'{ncch_file} - is_decrypted: {is_decrypted}, uses_seed: {uses_seed}')
                
                if uses_seed:
                    logger.info(f'*** {ncch_file} USES SEED CRYPTO ***')
            
            # Decrypt NCCH using NCCHReader.decrypt() for minimal flag changes
            if not is_decrypted:
                logger.info(f'Decrypting NCCH with minimal flag changes: {ncch_file}')
                
                ncch = NCCHReader(ncch_file, dev=cdn_dev)
                decrypted_file = ncch.decrypt()  # Returns the output filename
                
                # Replace original with decrypted version
                os.remove(ncch_file)
                shutil.move(decrypted_file, ncch_file)
                
                logger.info(f'Successfully decrypted NCCH: {ncch_file}')
            else:
                logger.info(f'NCCH already decrypted: {ncch_file}')
    
    # Read original TMD for metadata preservation
    tmd_extracted = tmd + '.extracted'
    t_orig = TMDReader(tmd_extracted)
    logger.debug(f'Original TMD has {len(t_orig.files)} content entries')
    
    # Calculate new hashes for decrypted content files
    content_info = []
    cf_sorted = sorted(cf)  # Ensure consistent order
    
    logger.debug(f'Original TMD content chunks:')
    for chunk in t_orig.content_chunks:
        logger.debug(f'  Index: {chunk.content_index}, ID: {chunk.contentID:08x}')
    
    logger.debug(f'Extracted content files: {cf_sorted}')
    
    for i, ncch_file in enumerate(cf_sorted):
        with open(ncch_file, 'rb') as f:
            content_data = f.read()
            content_hash = hashlib.sha256(content_data).digest()
            content_size = len(content_data)
        
        # Get original content info from TMD content chunks
        original_chunk = None
        for chunk in t_orig.content_chunks:
            # Match by filename pattern: index.contentID.ext
            expected_name = f'{hex(chunk.content_index)[2:].zfill(4)}.{hex(chunk.contentID)[2:].zfill(8)}.ncch'
            logger.debug(f'  Checking {ncch_file} against expected {expected_name}')
            if ncch_file == expected_name:
                original_chunk = chunk
                logger.debug(f'  ✅ Matched {ncch_file} to content {chunk.contentID:08x}')
                break
        
        if original_chunk is None:
            # Fallback: use index-based matching
            original_chunk = t_orig.content_chunks[i]
            logger.warning(f'No filename match for {ncch_file}, using index-based matching to content {original_chunk.contentID:08x}')
        
        content_info.append({
            'id': original_chunk.contentID,
            'index': original_chunk.content_index, 
            'type': original_chunk.content_type & ~0x0001,  # Preserve all flags except encryption flag
            'size': content_size,
            'hash': content_hash
        })
        
        logger.debug(f'Content {original_chunk.contentID:08x}: {ncch_file} -> size={content_size}, hash={content_hash.hex()[:16]}...')
    
    # Build new TMD with preserved signature and updated content info  
    tmd_new = 'tmd.decrypted'
    logger.info(f'Building TMD with preserved signature: {tmd_new}')
    
    TMDBuilder(
        tmd=tmd_extracted,
        content_info=content_info,
        preserve_signature=True,
        out=tmd_new
    )
    
    # Handle ticket
    if tik == '':
        tikBuilder(titleID=t_orig.titleID, title_ver=t_orig.hdr.title_ver, 
                  titlekey=hex(readbe(cdn.titlekey))[2:].zfill(32), 
                  regen_sig=regen_sig, out='tik')
        tik = 'tik'
        tik_to_cleanup = ['tik']
    else:
        tik_extracted = tik + '.extracted'
        tik = tik_extracted
        tik_to_cleanup = [tik_extracted]

    # Determine if meta should be included
    meta = 1
    if t_orig.titleID[3:5] == '48':
        meta = 0
    
    # Debug: Check final TMD content before building CIA
    debug_tmd = TMDReader(tmd_new)
    logger.debug('Final TMD content info:')
    for fname, finfo in debug_tmd.files.items():
        hash_hex = finfo['hash'].hex() if 'hash' in finfo else None
        logger.debug(f'  {fname}: size={finfo.get("size")}, type={finfo.get("type")}, hash={hash_hex}')
    
    # Build the final CIA
    logger.info(f'Building final CIA: {out}')
    CIABuilder(content_files=cf_sorted, tik=tik, tmd=tmd_new, meta=meta, dev=cia_dev, out='tmp.cia')
    
    # Clean up temporary files
    cleanup_files = cf_sorted + tik_to_cleanup + [tmd_extracted, tmd_new]
    
    # Also clean up any pattern-based files that might be left over
    for pattern_file in os.listdir('.'):
        if pattern_file.startswith('tmd.') and pattern_file.endswith('.extracted'):
            if pattern_file not in cleanup_files:
                cleanup_files.append(pattern_file)
        elif pattern_file.endswith('.ncch') and pattern_file not in cleanup_files:
            cleanup_files.append(pattern_file)
        elif pattern_file == 'cetk.extracted' and pattern_file not in cleanup_files:
            cleanup_files.append(pattern_file)
    
    for i in cleanup_files:
        if os.path.isfile(i):
            logger.debug(f'Cleaning up: {i}')
            os.remove(i)

    shutil.move('tmp.cia', '../tmp.cia')
    os.chdir('..')
    shutil.move('tmp.cia', out)
    
    logger.info(f'Successfully created reversible decrypted CIA: {out}')
    print(f"Created reversible decrypted CIA: {out}")
    print("This CIA uses minimal NCCH flag changes and preserves the original TMD signature for maximum reversibility.")
    
    return out

def cia_re_encrypt(reversible_cia_path, out='', cia_dev=0):
    """
    Re-encrypt a reversible decrypted CIA back to its original encrypted state.
    This reverses the cdn2cia_reversible_decrypt process.
    
    Args:
        reversible_cia_path: Path to the reversible decrypted CIA
        out: Output path for re-encrypted CIA
        cia_dev: Whether to use dev crypto (0=retail, 1=dev)
    
    Returns:
        Path to the re-encrypted CIA
    """
    logger = logging.getLogger(__name__)
    
    name = os.path.splitext(os.path.basename(reversible_cia_path))[0]
    if out == '':
        if name.endswith('.decrypted'):
            out = name[:-10] + '.re_encrypted.cia'
        else:
            out = f'{name}.re_encrypted.cia'
    
    # Extract the reversible CIA
    cia = CIAReader(reversible_cia_path, cia_dev)
    cia.extract()
    
    # Clean up CIA components we don't need
    for cleanup_file in ['cia_header.bin', 'cert.bin', 'meta.bin']:
        if os.path.isfile(cleanup_file):
            os.remove(cleanup_file)
    
    # Get content files and TMD
    cf = [i for i in os.listdir('.') if i.endswith('.ncch') or i.endswith('.nds')]
    # Filter out any backup files that might have been created
    cf = [f for f in cf if not f.startswith('first_content.')]
    tmd_file = 'tmd'
    tik_file = 'tik'
    
    # Read the current (decrypted) TMD to get metadata
    tmd_reader = TMDReader(tmd_file, cia_dev)
    logger.info(f'Current TMD has {len(tmd_reader.files)} content entries')
    
    # Re-encrypt NCCH files
    encrypted_files = []
    for ncch_file in cf:
        if ncch_file.endswith('.ncch'):
            logger.info(f'Re-encrypting NCCH: {ncch_file}')
            ncch = NCCHReader(ncch_file, dev=cia_dev)
            
            if ncch.is_decrypted:
                encrypted_file = ncch.encrypt()
                
                # Replace decrypted with encrypted version
                os.remove(ncch_file)
                shutil.move(encrypted_file, ncch_file)
                logger.info(f'Successfully re-encrypted NCCH: {ncch_file}')
            else:
                logger.info(f'NCCH already encrypted: {ncch_file}')
        encrypted_files.append(ncch_file)
    
    # Calculate new hashes for re-encrypted content files and build encrypted TMD
    content_info = []
    cf_sorted = sorted(cf)  # Ensure consistent order
    
    for i, ncch_file in enumerate(cf_sorted):
        with open(ncch_file, 'rb') as f:
            content_data = f.read()
            content_hash = hashlib.sha256(content_data).digest()
            content_size = len(content_data)
        
        # Get original content info from decrypted TMD
        # Extract content info from filename (format: index.contentID.ext)
        filename_parts = ncch_file.split('.')
        content_index = int(filename_parts[0], 16)
        content_id = int(filename_parts[1], 16)
        
        content_info.append({
            'id': content_id,
            'index': content_index,
            'type': 0x1,  # Set to encrypted (standard)
            'size': content_size,
            'hash': content_hash
        })
    
    # Build new TMD with encrypted content flags and preserved signature
    tmd_encrypted = 'tmd.encrypted'
    TMDBuilder(
        tmd=tmd_file,
        content_info=content_info,
        crypt=1,  # Set encrypted flag
        out=tmd_encrypted
    )
    
    # Use the encrypted TMD
    os.remove(tmd_file)
    shutil.move(tmd_encrypted, tmd_file)
    
    # Check if ticket has valid signature, generate fake one if needed
    tik_read = tikReader(tik_file)
    if not tik_read.verify()[0][1]:  # Ticket has invalid sig
        logger.info('Regenerating ticket with fake signature')
        regen_sig = 'dev' if cia_dev else 'retail'
        tikBuilder(
            titleID=tmd_reader.titleID,
            title_ver=tmd_reader.hdr.title_ver,
            regen_sig=regen_sig,
            out='tik_new'
        )
        os.remove(tik_file)
        shutil.move('tik_new', tik_file)
    
    # Build the re-encrypted CIA
    meta = 1
    if tmd_reader.titleID[3:5] == '48':
        meta = 0
    
    CIABuilder(content_files=cf, tik=tik_file, tmd=tmd_file, meta=meta, dev=cia_dev, out=out)
    
    # Cleanup
    for cleanup_file in [tik_file, tmd_file] + cf:
        if os.path.isfile(cleanup_file):
            os.remove(cleanup_file)
    
    logger.info(f'Re-encrypted CIA saved to: {out}')
    return out

def cia2cdn_encrypted(reversible_cia_path, out='', cia_dev=0, titlekey=''):
    """
    Convert a reversible decrypted CIA back to original encrypted CDN format.
    This completes the full round-trip: CDN → Decrypted CIA → Original CDN.
    
    Args:
        reversible_cia_path: Path to the reversible decrypted CIA
        out: Output directory name for CDN files
        cia_dev: Whether CIA uses dev crypto (0=retail, 1=dev)
        titlekey: Optional titlekey override (hex string)
    
    Returns:
        Path to the output CDN directory
    """
    logger = logging.getLogger(__name__)
    
    name = os.path.splitext(os.path.basename(reversible_cia_path))[0]
    if out == '':
        if name.endswith('.decrypted'):
            out = name[:-10] + '_reconstructed_cdn'
        else:
            out = f'{name}_reconstructed_cdn'
    
    # Extract the reversible CIA
    logger.info(f'Extracting reversible decrypted CIA: {reversible_cia_path}')
    cia = CIAReader(reversible_cia_path, cia_dev)
    cia.extract()
    
    # Clean up CIA components we don't need
    for cleanup_file in ['cia_header.bin', 'cert.bin', 'meta.bin']:
        if os.path.isfile(cleanup_file):
            os.remove(cleanup_file)
    
    # Get content files and TMD/TIK
    cf = [i for i in os.listdir('.') if i.endswith('.ncch') or i.endswith('.nds')]
    tmd_file = 'tmd'
    tik_file = 'tik'
    
    # Read the current (decrypted) TMD to get metadata
    tmd_reader = TMDReader(tmd_file, cia_dev)
    logger.info(f'TMD has {len(tmd_reader.files)} content entries')
    
    # Re-encrypt NCCH files
    logger.info('Re-encrypting NCCH files...')
    for ncch_file in cf:
        if ncch_file.endswith('.ncch'):
            logger.debug(f'Processing NCCH: {ncch_file}')
            ncch = NCCHReader(ncch_file, dev=cia_dev)
            
            if ncch.is_decrypted:
                logger.info(f'Re-encrypting NCCH: {ncch_file}')
                encrypted_file = ncch.encrypt()
                
                # Replace decrypted with encrypted version
                os.remove(ncch_file)
                shutil.move(encrypted_file, ncch_file)
                logger.debug(f'Successfully re-encrypted: {ncch_file}')
            else:
                logger.debug(f'NCCH already encrypted: {ncch_file}')
    
    # Calculate new hashes for re-encrypted content files
    content_info = []
    cf_sorted = sorted(cf)  # Ensure consistent order
    
    for i, ncch_file in enumerate(cf_sorted):
        with open(ncch_file, 'rb') as f:
            content_data = f.read()
            content_hash = hashlib.sha256(content_data).digest()
            content_size = len(content_data)
        
        # Get original content info from decrypted TMD
        # Find the matching content chunk by filename pattern
        original_chunk = None
        for chunk in tmd_reader.content_chunks:
            expected_name = f'{hex(chunk.content_index)[2:].zfill(4)}.{hex(chunk.contentID)[2:].zfill(8)}.ncch'
            if ncch_file == expected_name:
                original_chunk = chunk
                break
        
        if original_chunk is None:
            # Fallback: use index-based matching
            original_chunk = tmd_reader.content_chunks[i]
            logger.warning(f'No filename match for {ncch_file}, using index-based matching')
        
        content_info.append({
            'id': original_chunk.contentID,
            'index': original_chunk.content_index,
            'type': original_chunk.content_type | 0x0001,  # Preserve all flags and add encryption flag
            'size': content_size,
            'hash': content_hash
        })
    
    # Build new TMD with encrypted content flags (for CDN) and preserved signature
    logger.info('Building encrypted TMD for CDN with preserved signature...')
    tmd_encrypted = 'tmd.encrypted'
    TMDBuilder(
        tmd=tmd_file,
        content_info=content_info,
        crypt=1,  # Set encrypted flag for CDN format
        out=tmd_encrypted
    )
    
    # Get titlekey from ticket or use provided one
    if titlekey == '':
        tik_read = tikReader(tik_file)
        titlekey_bytes = tik_read.titlekey
        titlekey = titlekey_bytes.hex()
        logger.debug(f'Using titlekey from ticket: {titlekey}')
    else:
        logger.debug(f'Using provided titlekey: {titlekey}')
    
    # Use CDNBuilder to create the final CDN structure
    logger.info(f'Building CDN structure in directory: {out}')
    CDNBuilder(
        content_files=cf_sorted,
        tik=tik_file if os.path.exists(tik_file) else '',
        tmd=tmd_encrypted,
        titlekey=titlekey,
        out=out
    )
    
    # Handle additional CDN files that aren't part of the CIA
    logger.info('Handling additional CDN files...')
    
    # Copy seeddb.bin if it exists in resources
    # Check multiple possible locations for seeddb.bin
    seeddb_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources', 'seeddb.bin'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib', 'resources', 'seeddb.bin'),
        os.path.join(os.getcwd(), 'resources', 'seeddb.bin'),
        os.path.join(os.getcwd(), 'seeddb.bin'),
    ]
    seeddb_source = None
    for path in seeddb_paths:
        if os.path.exists(path):
            seeddb_source = path
            break
    
    # Cleanup temporary files
    cleanup_files = cf_sorted + [tik_file, tmd_file, tmd_encrypted]
    for cleanup_file in cleanup_files:
        if os.path.isfile(cleanup_file):
            logger.debug(f'Cleaning up: {cleanup_file}')
            os.remove(cleanup_file)
    
    logger.info(f'Successfully reconstructed CDN in directory: {out}')
    print(f"Reconstructed CDN files in: {out}")
    print("This CDN contains the original encrypted content reconstructed from the reversible CIA.")
    
    return out

def cia2cia(path, out='', cia_dev=0, force_mode=''):
    """
    Smart CIA cross-crypto converter that auto-detects encryption state and flips it.
    Converts encrypted CIAs to decrypted CIAs and vice versa.
    
    Args:
        path: Path to input CIA file
        out: Output CIA filename (auto-generated if empty)
        cia_dev: Whether CIA uses dev crypto (0=retail, 1=dev)
        force_mode: Force specific mode ('encrypt', 'decrypt', or '' for auto-detect)
    
    Returns:
        Path to the converted CIA
    """
    logger = logging.getLogger(__name__)
    
    name = os.path.splitext(os.path.basename(path))[0]
    
    # Extract CIA to analyze content state
    logger.info(f'Analyzing CIA: {path}')
    cia = CIAReader(path, cia_dev)
    cia.extract()
    
    # Read TMD to check encryption state
    tmd_reader = TMDReader('tmd', cia_dev)
    cf = [i for i in os.listdir('.') if i.endswith('.ncch') or i.endswith('.nds')]
    
    # Determine current encryption state
    is_decrypted_content = False
    is_encrypted_content = False
    
    # Check TMD content type flags
    for chunk in tmd_reader.content_chunks:
        if (chunk.content_type & 1) == 0:  # Missing encryption flag
            is_decrypted_content = True
        else:  # Has encryption flag
            is_encrypted_content = True
    
    # Also check actual NCCH files for encryption state
    actual_decrypted = 0
    actual_encrypted = 0
    
    for ncch_file in cf:
        if ncch_file.endswith('.ncch'):
            ncch = NCCHReader(ncch_file, dev=cia_dev)
            if ncch.is_decrypted:
                actual_decrypted += 1
            else:
                actual_encrypted += 1
    
    # Clean up extracted files first
    for cleanup_file in ['cia_header.bin', 'cert.bin', 'tmd', 'tik', 'meta.bin'] + cf:
        if os.path.isfile(cleanup_file):
            os.remove(cleanup_file)
    
    # Determine what operation to perform
    if force_mode == 'encrypt':
        target_mode = 'encrypt'
        logger.info('Force mode: Converting to encrypted CIA')
    elif force_mode == 'decrypt':
        target_mode = 'decrypt'
        logger.info('Force mode: Converting to decrypted CIA')
    else:
        # Auto-detect based on current state
        if is_decrypted_content or actual_decrypted > actual_encrypted:
            target_mode = 'encrypt'
            logger.info('Auto-detected decrypted content - converting to encrypted CIA')
        elif is_encrypted_content or actual_encrypted > actual_decrypted:
            target_mode = 'decrypt'
            logger.info('Auto-detected encrypted content - converting to decrypted CIA')
        else:
            logger.warning('Unable to determine encryption state - defaulting to decrypt')
            target_mode = 'decrypt'
    
    # Generate output filename if not provided
    if out == '':
        if target_mode == 'encrypt':
            if name.endswith('.decrypted'):
                out = name[:-10] + '.encrypted.cia'
            else:
                out = f'{name}.encrypted.cia'
        else:  # decrypt
            if name.endswith('.encrypted'):
                out = name[:-10] + '.decrypted.cia'
            else:
                out = f'{name}.decrypted.cia'
    
    # Perform the conversion
    if target_mode == 'encrypt':
        # Convert decrypted CIA to encrypted CIA
        logger.info('Re-encrypting CIA content...')
        result = cia_re_encrypt(path, out, cia_dev)
    else:
        # Convert encrypted CIA to decrypted CIA via CDN round-trip
        # This ensures we get a proper reversible decrypted CIA
        logger.info('Decrypting CIA content via CDN conversion...')
        
        # First convert to CDN
        temp_cdn_dir = f'temp_cdn_{name}'
        cia2cdn_encrypted(path, temp_cdn_dir, cia_dev)
        
        # Then convert back to decrypted CIA with reversible mode
        result = cdn2cia_reversible_decrypt(temp_cdn_dir, out, '', 0, cia_dev)
        
        # Clean up temporary CDN directory
        if os.path.exists(temp_cdn_dir):
            shutil.rmtree(temp_cdn_dir)
    
    logger.info(f'CIA conversion completed: {result}')
    print(f"Converted CIA: {path} -> {result}")
    print(f"Operation: {target_mode.title()}ed CIA content")
    
    return result
