# 3ds_decrypt for python3

from Crypto.Cipher import AES
from Crypto.Util import Counter
from sys import argv
import struct

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def to_bytes(num):
    return num.to_bytes(16, byteorder='big')
    # numstr = ''
    # tmp = num
    # while len(numstr) < 16:
    #     numstr += chr(tmp & 0xFF)
    #     tmp >>= 8
    # return numstr[::-1].encode()

# Setup Keys and IVs
plain_counter = struct.unpack('>Q', b'\x01\x00\x00\x00\x00\x00\x00\x00')
exefs_counter = struct.unpack('>Q', b'\x02\x00\x00\x00\x00\x00\x00\x00')
romfs_counter = struct.unpack('>Q', b'\x03\x00\x00\x00\x00\x00\x00\x00')
Constant = struct.unpack('>QQ', b'\x1F\xF9\xE9\xAA\xC5\xFE\x04\x08\x02\x45\x91\xDC\x5D\x52\x76\x8A') # 3DS AES Hardware Constant

#Retail keys
KeyX0x18 = struct.unpack('>QQ', b'\x82\xE9\xC9\xBE\xBF\xB8\xBD\xB8\x75\xEC\xC0\xA0\x7D\x47\x43\x74') # KeyX 0x18 (New 3DS 9.3)
KeyX0x1B = struct.unpack('>QQ', b'\x45\xAD\x04\x95\x39\x92\xC7\xC8\x93\x72\x4A\x9A\x7B\xCE\x61\x82') # KeyX 0x1B (New 3DS 9.6)
KeyX0x25 = struct.unpack('>QQ', b'\xCE\xE7\xD8\xAB\x30\xC0\x0D\xAE\x85\x0E\xF5\xE3\x82\xAC\x5A\xF3') # KeyX 0x25 (> 7.x)
KeyX0x2C = struct.unpack('>QQ', b'\xB9\x8E\x95\xCE\xCA\x3E\x4D\x17\x1F\x76\xA9\x4D\xE9\x34\xC0\x53') # KeyX 0x2C (< 6.x)

# Dev Keys: (Uncomment these lines if your 3ds rom is encrypted with Dev Keys)
#KeyX0x18 = struct.unpack('>QQ', b'\x30\x4B\xF1\x46\x83\x72\xEE\x64\x11\x5E\xBD\x40\x93\xD8\x42\x76') # Dev KeyX 0x18 (New 3DS 9.3)
#KeyX0x1B = struct.unpack('>QQ', b'\x6C\x8B\x29\x44\xA0\x72\x60\x35\xF9\x41\xDF\xC0\x18\x52\x4F\xB6') # Dev KeyX 0x1B (New 3DS 9.6)
#KeyX0x25 = struct.unpack('>QQ', b'\x81\x90\x7A\x4B\x6F\x1B\x47\x32\x3A\x67\x79\x74\xCE\x4A\xD7\x1B') # Dev KeyX 0x25 (> 7.x)
#KeyX0x2C = struct.unpack('>QQ', b'\x51\x02\x07\x51\x55\x07\xCB\xB1\x8E\x24\x3D\xCB\x85\xE2\x3A\x1D') # Dev KeyX 0x2C (< 6.x)

with open(argv[1], 'rb+') as f, open('b2', 'wb') as gg:

    def f_read(size):
        pos = f.tell()
        data = f.read(size)
        f.seek(pos)
        return data

    print(argv[1]) # Print the filename of the file being decrypted
    f.seek(0x100) # Seek to start of NCSD header
    magic = f.read(0x04)
    if magic == b"NCSD":

        f.seek(0x188)
        ncsd_flags = struct.unpack('<BBBBBBBB', f.read(0x8))
        sectorsize = 0x200 * (2**ncsd_flags[6])

        for p in range(8):
            f.seek((0x120) + (p*0x08)) # Seek to start of partition information, read offsets and lengths
            part_off = struct.unpack('<L', f.read(0x04))
            part_len = struct.unpack('<L', f.read(0x04))
            part_start = part_off[0] * sectorsize

            f.seek(part_start + 0x188) # Get the partition flags to determine encryption type.
            partition_flags = struct.unpack('<BBBBBBBB', f.read(0x8))

            if (partition_flags[7] & 0x04): # check if the 'NoCrypto' bit (bit 3) is set
                print("Partition %1d: Already Decrypted?..." % p)
            else:
                if part_start > 0: # check if partition exists

                    f.seek(part_start + 0x100) # Find partition start (+ 0x100 to skip NCCH header)
                    magic = f.read(0x04)

                    if magic == b"NCCH": # check if partition is valid
                        f.seek(part_start + 0x0)
                        part_keyy = struct.unpack('>QQ', f.read(0x10)) # KeyY is the first 16 bytes of partition RSA-2048 SHA-256 signature

                        f.seek(part_start + 0x108)
                        tid = struct.unpack('<Q', f.read(0x8)) # TitleID is used as IV joined with the content type.
                        plain_iv = tid + plain_counter # Get the IV for plain sector (TitleID + Plain Counter)
                        exefs_iv = tid + exefs_counter # Get the IV for ExeFS (TitleID + ExeFS Counter)
                        romfs_iv = tid + romfs_counter # Get the IV for RomFS (TitleID + RomFS Counter)

                        f.seek(part_start + 0x160) # get exheader hash
                        exhdr_sbhash = "%016X%016X%016X%016X" % struct.unpack('>QQQQ', f.read(0x20))

                        f.seek(part_start + 0x180)
                        exhdr_len = struct.unpack('<L', f.read(0x04)) # get extended header length

                        f.seek(part_start + 0x190)
                        plain_off = struct.unpack('<L', f.read(0x04)) # get plain sector offset
                        plain_len = struct.unpack('<L', f.read(0x04)) # get plain sector length

                        f.seek(part_start + 0x198)
                        logo_off = struct.unpack('<L', f.read(0x04)) # get logo offset
                        logo_len = struct.unpack('<L', f.read(0x04)) # get logo length

                        f.seek(part_start + 0x1A0)
                        exefs_off = struct.unpack('<L', f.read(0x04)) # get exefs offset
                        exefs_len = struct.unpack('<L', f.read(0x04)) # get exefs length

                        f.seek(part_start + 0x1B0)
                        romfs_off = struct.unpack('<L', f.read(0x04)) # get romfs offset
                        romfs_len = struct.unpack('<L', f.read(0x04)) # get romfs length

                        f.seek(part_start + 0x1C0) # get exefs hash
                        exefs_sbhash = "%016X%016X%016X%016X" % struct.unpack('>QQQQ', f.read(0x20))

                        f.seek(part_start + 0x1E0) # get romfs hash
                        romfs_sbhash = str("%016X%016X%016X%016X") % (struct.unpack('>QQQQ', f.read(0x20)))

                        plainIV = int("%016X%016X" % plain_iv, 16)
                        exefsIV = int("%016X%016X" % exefs_iv, 16)
                        romfsIV = int("%016X%016X" % romfs_iv, 16)
                        KeyY = int("%016X%016X" % part_keyy, 16)
                        Const = int("%016X%016X" % Constant, 16)

                        KeyX2C = int("%016X%016X" % KeyX0x2C, 16)
                        NormalKey2C = rol((rol(KeyX2C, 2, 128) ^ KeyY) + Const, 87, 128)

                        if (partition_flags[3] == 0x00): # Uses Original Key
                            KeyX = int("%016X%016X" % KeyX0x2C, 16)
                        elif (partition_flags[3] == 0x01): # Uses 7.x Key
                            KeyX = int("%016X%016X" % KeyX0x25, 16)
                        elif (partition_flags[3] == 0x0A): # Uses New3DS 9.3 Key
                            KeyX = int("%016X%016X" % KeyX0x18, 16)
                        elif (partition_flags[3] == 0x0B): # Uses New3DS 9.6 Key
                            KeyX = int("%016X%016X" % KeyX0x1B, 16)
                        NormalKey = rol((rol(KeyX, 2, 128) ^ KeyY) + Const, 87, 128)

                        if (partition_flags[7] & 0x01): # fixed crypto key (aka 0-key)
                            NormalKey = 0x00
                            NormalKey2C = 0x00

                        if (exhdr_len[0] > 0):
                            # decrypt exheader
                            f.seek(part_start + sectorsize)
                            exhdr_filelen = 0x800
                            exefsctr2C = Counter.new(128, initial_value=(plainIV))
                            exefsctrmode2C = AES.new(to_bytes(NormalKey2C), AES.MODE_CTR, counter=exefsctr2C)
                            print("Partition %1d ExeFS: Decrypting: ExHeader" % p)
                            f.write(exefsctrmode2C.decrypt(f_read(exhdr_filelen)))

                        if (exefs_len[0] > 0):
                            # decrypt exefs filename table
                            part_exefs_start = (part_off[0] + exefs_off[0]) * sectorsize
                            f.seek(part_exefs_start)
                            exefsctr2C = Counter.new(128, initial_value=(exefsIV))
                            exefsctrmode2C = AES.new(to_bytes(NormalKey2C), AES.MODE_CTR, counter=exefsctr2C)
                            f.write(exefsctrmode2C.decrypt(f_read(sectorsize)))
                            print("Partition %1d ExeFS: Decrypting: ExeFS Filename Table" % p)

                            if ( partition_flags[3] == 0x01 or partition_flags[3] == 0x0A or partition_flags[3] == 0x0B ):
                                code_filelen = 0
                                for j in range(10): # 10 exefs filename slots
                                    # get filename, offset and length
                                    f.seek(part_exefs_start + j*0x10)
                                    exefs_filename = struct.unpack('<8s', f.read(0x08))
                                    if exefs_filename[0] == b".code\x00\x00\x00":
                                        code_fileoff = struct.unpack('<L', f.read(0x04))
                                        code_filelen = struct.unpack('<L', f.read(0x04))
                                        datalenM = ((code_filelen[0]) // (1024*1024))
                                        datalenB = ((code_filelen[0]) % (1024*1024))
                                        ctroffset = ((code_fileoff[0] + sectorsize) // 0x10)
                                        exefsctr = Counter.new(128, initial_value=(exefsIV + ctroffset))
                                        exefsctr2C = Counter.new(128, initial_value=(exefsIV + ctroffset))
                                        exefsctrmode = AES.new(to_bytes(NormalKey), AES.MODE_CTR, counter=exefsctr)
                                        exefsctrmode2C = AES.new(to_bytes(NormalKey2C), AES.MODE_CTR, counter=exefsctr2C)
                                        f.seek((((part_off[0] + exefs_off[0]) + 1) * sectorsize) + code_fileoff[0])
                                        if (datalenM > 0):
                                            for i in range(datalenM):
                                                f.write(exefsctrmode2C.encrypt(exefsctrmode.decrypt(f_read(1024*1024))))
                                                print("\rPartition %1d ExeFS: Decrypting: %8s... %4d / %4d mb..." % (p, str(exefs_filename[0]), i, datalenM + 1), end=' ')
                                        if (datalenB > 0):
                                            f.write(exefsctrmode2C.encrypt(exefsctrmode.decrypt(f_read(datalenB))))
                                        print("\rPartition %1d ExeFS: Decrypting: %8s... %4d / %4d mb... Done!" % (p, str(exefs_filename[0]), datalenM + 1, datalenM + 1))

                            f.flush()

                            # decrypt exefs
                            exefsSizeM = ((exefs_len[0] - 1) * sectorsize) // (1024*1024)
                            exefsSizeB = ((exefs_len[0] - 1) * sectorsize) % (1024*1024)
                            ctroffset = (sectorsize // 0x10)
                            exefsctr2C = Counter.new(128, initial_value=(exefsIV + ctroffset))
                            exefsctrmode2C = AES.new(to_bytes(NormalKey2C), AES.MODE_CTR, counter=exefsctr2C)
                            f.seek((part_off[0] + exefs_off[0] + 1) * sectorsize)
                            if (exefsSizeM > 0):
                                for i in range(exefsSizeM):
                                    f.write(exefsctrmode2C.decrypt(f_read(1024*1024)))
                                    print("\rPartition %1d ExeFS: Decrypting: %4d / %4d mb" % (p, i, exefsSizeM + 1), end=' ')
                            if (exefsSizeB > 0):
                                f.write(exefsctrmode2C.decrypt(f_read(exefsSizeB)))
                            print("\rPartition %1d ExeFS: Decrypting: %4d / %4d mb... Done" % (p, exefsSizeM + 1, exefsSizeM + 1))

                        else:
                            print("Partition %1d ExeFS: No Data... Skipping..." % p)

                        if (romfs_off[0] != 0):
                            romfsSizeM = (romfs_len[0] * sectorsize) // (1024*1024)
                            romfsSizeB = (romfs_len[0] * sectorsize) % (1024*1024)

                            romfsctr = Counter.new(128, initial_value=romfsIV)
                            romfsctrmode = AES.new(to_bytes(NormalKey), AES.MODE_CTR, counter=romfsctr)

                            f.seek((part_off[0] + romfs_off[0]) * sectorsize)
                            if (romfsSizeM > 0):
                                for i in range(romfsSizeM):
                                    f.write(romfsctrmode.decrypt(f_read(1024*1024)))
                                    print("\rPartition %1d RomFS: Decrypting: %4d / %4d mb" % (p, i, romfsSizeM + 1), end=' ')
                            if (romfsSizeB > 0):
                                f.write(romfsctrmode.decrypt(f_read(romfsSizeB)))

                            print("\rPartition %1d RomFS: Decrypting: %4d / %4d mb... Done" % (p, romfsSizeM + 1, romfsSizeM + 1))

                        else:
                            print("Partition %1d RomFS: No Data... Skipping..." % p)

                        f.seek(part_start + 0x18B)
                        f.write(b'\x00') # set crypto-method to 0x00
                        f.seek(part_start + 0x18F)
                        flag = int(partition_flags[7]) # read partition flag
                        flag = (flag & ((0x01|0x20)^0xFF)) # turn off 0x01 = FixedCryptoKey and 0x20 = CryptoUsingNewKeyY
                        flag = (flag | 0x04) # turn on 0x04 = NoCrypto
                        f.write(struct.pack('<B', int(flag))) # write flag

                    else:
                        print("Partition %1d Unable to read NCCH header" % p)
                else:
                    print("Partition %1d Not found... Skipping..." % p)
        print("Done...")
    else:
        print("Error: Not a 3DS Rom?")
