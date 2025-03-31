import sys, os, struct, subprocess


# global variables:
includeSegmented = True
maxSymbolSize = 0xFFFFF


# file path args:
path_sm64_prelim_elf = sys.argv[1] # sm64_prelim.elf
path_addr_bin        = sys.argv[2] # addr.bin
path_name_bin        = sys.argv[3] # name.bin
path_debug_map_txt   = sys.argv[4] # debug_map.txt


class MapSymbol():
	def __init__(self, addr, size, name, type, errc):
		self.addr = addr # Symbol address (32 bits).
		# self.segment = ((addr >> 24) & 0xFF) # 0xXX000000
		# self.lowAddr = (addr & 0xFFFFFF) # 0x00XXXXXX
		self.size = size # Symbol size (32 bits).
		self.name = name # Symbol name (string).
		self.strlen = ((len(name) + 4) & (~3)) # Symbol name length (16 bits).
		self.type = type # Symbol type (8 bits).
		self.errc = errc # Error char (8 bits).
	def __str__(self):
		return "%s %d %s %hi %c %c" % (self.addr, self.size, self.name, self.strlen, self.type, self.errc)
	def __repr__(self):
		return "%s %d %s %hi %c %c" % (self.addr, self.size, self.name, self.strlen, self.type, self.errc)


# See struct MapSymbol in map_parser.h.
structDef = ">LLLHBB"

symNames = []

proc = subprocess.Popen(["nm", "--print-size", "--numeric-sort", path_sm64_prelim_elf], stdout=subprocess.PIPE)

symbols = proc.communicate()[0].decode('ascii').split("\n")

for line in symbols:
	# Format:
	# [address] [size]   [type] [name]
	# 80153210  000000f8 T      global_sym
	# OR:
	# [address] [type] [name]
	# 80153210  t      static_sym
	tokens = line.split()
	if (len(tokens) >= 3) and (len(tokens[-2]) == 1):
		addr = int(tokens[0], 16)
		# Error char.
		errc = ord('\0')
		# Skip non-segmented addresses if includeSegmented is False.
		if (includeSegmented or (addr & 0x80000000)):
			# If this is not the first entry...
			if symNames:
				# Get the previous entry.
				prevEntry = symNames[-1]
				# If the previous entry does not have a defined size...
				if (prevEntry.size == 0) and (addr > prevEntry.addr):
					# Get the size between the current entry and the previous entry.
					sizeToLastEntry = (addr - prevEntry.addr)
					# If the distance to the previous entry is not unreasonably large, use it as the symbol's size.
					if (sizeToLastEntry < maxSymbolSize):
						prevEntry.size = sizeToLastEntry
					else:
						# Size too large, set error char 'S'.
						errc = ord('S')
			# Last token is the name.
			name = tokens[-1]
			# Second to last token is the type char.
			type = ord(tokens[-2])
			# Check for size data.
			if (len(tokens) < 4):
				# No size data, so assume 0 for now. It may be set by the next entry.
				size = 0
			else:
				# Get the size data.
				size = int(tokens[-3], 16)
			# Append the symbol to the list.
			symNames.append(MapSymbol(addr, size, name, type, errc))


addrFile = open(path_addr_bin, "wb+") # addr.bin
nameFile = open(path_name_bin, "wb+") # name.bin

symNames.sort(key=lambda x: x.addr) # TODO: x.lowAddr to sort segmented addresses

nameOffset = 0 # Symbol name offset (32 bits).
for x in symNames:
	addrFile.write(struct.pack(structDef, x.addr, x.size, nameOffset, len(x.name), x.type, x.errc))
	nameFile.write(struct.pack((">%ds" % x.strlen), bytes(x.name, encoding="ascii")))
	nameOffset += x.strlen

addrFile.close()
nameFile.close()


# Get sizes for linkerscript:
with open(path_debug_map_txt, "w+") as f:
	addr_size = os.path.getsize(path_addr_bin)
	name_size = os.path.getsize(path_name_bin)
	f.write("DEBUG_MAP_DATA_ADDR_SIZE = 0x%X;\nDEBUG_MAP_DATA_NAME_SIZE = 0x%x;\nDEBUG_MAP_DATA_SIZE = 0x%X;" % (addr_size, name_size, (addr_size + name_size)))

# print('\n'.join([str(hex(x.addr)) + " " + x.name for x in symNames]))

