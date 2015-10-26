import os, struct, zlib
import argparse
from io import BytesIO

"""
This script extracts patch data for SSB4, working on v 174.
You must first download the data from NUS, then decrypt it.

File structure from the version root:
	code/...
	meta/...
	content/
		patch/
			data/...
			patchlist
			resource
"""

argp = argparse.ArgumentParser(description='Extract SSB4 version update data.')
argp.add_argument('--datadir', default=os.getcwd())
argp.add_argument('--outdir', default=os.getcwd())
args = argp.parse_args()

plfp = open(os.path.join(args.datadir, 'content/patch/patchlist'), 'rb')
rffp = open(os.path.join(args.datadir, 'content/patch/resource'), 'rb')

def read_int(fh, count=1):
	ret = struct.unpack('<{}I'.format(count), fh.read(4 * count))
	if len(ret) == 1:
		return ret[0]
	else:
		return ret

# Read the list of files contained in patch
plfp.read(4) # 01 00 50 4C "..PL" header
pl_count = read_int(plfp)
plfp.read(4 * 30) # There might be useful information in these bytes
pl_index = []
pl_raw_count = 0

for i in range(pl_count):
	fn = plfp.read(128)
	if b'\0' in fn:
		fn = fn[:fn.find(b'\0')]

	# This script only cares about 'packed' files
	pl_raw_count += 1
	if fn[-7:] == b'/packed':
		fn = fn[:-6] # include trailing slash
		pl_index.append(str(fn, 'utf-8'))

print('Patchlist: {} packed archives (out of {} patch files)'.format(len(pl_index), pl_raw_count))

# Decompress the resource archive
rffp.read(4) # 52 46 06 00 "RF.." header
rf_comp_offset = read_int(rffp)
rffp.read(8)
rf_count, timestamp, rf_comp_len, rf_decomp_len, \
rf_str_offset, rf_str_len = struct.unpack('<6I', rffp.read(24))
rffp.seek(rf_comp_offset)
rf_data = zlib.decompress(rffp.read())
rdfp = BytesIO(rf_data)
rdfp.seek(rf_str_offset - rf_comp_offset)

print('Resource: {} entries'.format(rf_count))

# Read resource data segments
# This is mostly taken verbatim from comex's dtls.py
seg_count = read_int(rdfp)
segments = [rdfp.read(0x2000) for seg in range(seg_count)]
def get_from_offset(off, len):
	seg_off = off & 0x1FFF
	return segments[int(off / 0x2000)][seg_off:seg_off + len]

# File names and extensions are stored separately
# Get the extensions first
offset_count = read_int(rdfp)
ext_offsets = read_int(rdfp, offset_count)
extensions = []
for i, ext_offset in enumerate(ext_offsets):
	ext = get_from_offset(ext_offset, 64)
	ext = ext[:ext.find(b'\0')]
	extensions.append(ext)

# Now we know segments and extensions, reset pointer
# Skip a bunch of irrelevant data
rdfp.seek(0)
size_unk = read_int(rdfp)
rdfp.read(size_unk * 8)
size_unk2 = read_int(rdfp)
rdfp.read(size_unk2)

dir_tree = []

packed_file = None
packed_fn = ''
packed_depth = 0

files_written = 0
bytes_written = 0

while rdfp.tell() < rf_count:
	# Read a single resource file definition
	res_off, res_fn_off_etc, res_size_comp, res_size_decomp, \
	res_timestamp, res_flags = read_int(rdfp, 6)
	res_ext_off = res_fn_off_etc >> 24
	res_fn_off = res_fn_off_etc & 0xFFFFF
	res_fn = get_from_offset(res_fn_off, 128)
	if res_fn_off_etc & 0x00800000:
		ref, = struct.unpack('<H', res_fn[:2])
		ref_len = (ref & 0x1F) + 4
		ref_rel_off = (ref & 0xE0) >> 6 << 8 | (ref >> 8)
		res_fn = get_from_offset(res_fn_off - ref_rel_off, ref_len) + res_fn[2:]
	if b'\0' in res_fn:
		res_fn = res_fn[:res_fn.find(b'\0')]
	res_fn += extensions[res_ext_off]

	res_depth = res_flags & 0xFF

	dir_tree = dir_tree[:res_depth - 1] + [res_fn]
	res_path = str(b''.join(dir_tree), 'utf-8')

	# TODO: support extracting localized files?
	if 'data/' + res_path in pl_index:
		if packed_file != None:
			packed_file.close()
		packed_fn = 'content/patch/data/' + res_path + 'packed'
		packed_file = open(os.path.join(args.datadir, packed_fn), 'rb')
		packed_size = os.path.getsize(os.path.join(args.datadir, packed_fn))
		print('Extracting {}packed ({} KB)...'.format(res_path, round(packed_size / 1024, 2)))
		packed_fn = res_path
		packed_depth = res_depth
	elif packed_file != None:
		if res_depth > packed_depth:
			if res_path[-1] == '/':
				os.makedirs(os.path.join(args.outdir, 'content/patch/data/' + res_path[:-1]), exist_ok=True)
			else:
				# Extract single file from packed data
				packed_file.seek(res_off)
				sr_data = packed_file.read(res_size_comp)
				# Check for zlib header
				if sr_data[:2] == b'\x78\x9C':
					sr_data = zlib.decompress(sr_data)

				# Warning: sr_data might be blank (Intended, I think)
				srfp = open(os.path.join(args.outdir, 'content/patch/data/' + res_path), 'wb')
				if srfp.write(sr_data):
					files_written += 1
					bytes_written += res_size_decomp
				srfp.close()
		else:
			# Reached a file unincluded in patch data
			packed_depth = 0
			packed_file.close()
			packed_file = None

MB_written = Math.round(bytes_written / (1024 * 1024), 2)
print('Extracted {} files, {} MB'.format(files_written, MB_written))
