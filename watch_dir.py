import os, time, pickle, hashlib, struct, random, sys, copy
from Crypto.Cipher import AES


def encrypt_file(path, dest):
	key = hashlib.sha256(PASSWORD).digest()
	IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	# open('test.bin', 'wb').write(IV)
	mode = AES.MODE_CBC
	encryptor = AES.new(key, mode, IV=IV)
	filesize = os.path.getsize(path)
	chunksize = 64*1024

	with open(path, 'rb') as infile:
		with open(dest, 'wb') as outfile:
			outfile.write(struct.pack('<Q', filesize))
			outfile.write(IV)

			while True:
				chunk = infile.read(chunksize)
				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
			    		chunk += b' ' * (16 - len(chunk) % 16)

				outfile.write(encryptor.encrypt(chunk))


def decrypt_file(path, dest):
	key = hashlib.sha256(PASSWORD).digest()
	mode = AES.MODE_CBC
	chunksize = 24*1024
	
	with open(path, 'rb') as infile:
		origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
		iv = infile.read(16)
		decryptor = AES.new(key, mode, iv)

		with open(dest, 'wb') as outfile:
			while True:
				chunk = infile.read(chunksize)
				if len(chunk) == 0:
			    		break
				write_some = decryptor.decrypt(chunk) 
				outfile.write(write_some)

			outfile.truncate(origsize)


def load_db(db_name):
	result = dict()
	with open(db_name, 'rb') as f:
		result = pickle.load(f)
	return result


def update_db(db, db_name):
	with open(db_name, 'wb') as f:
		pickle.dump(db, f)
	print("[database] updated")


def upload_file(path, target):
	sys.stdout.write("[local] change detected: %s ..." % path)
	enc_file = os.path.join(target, os.path.basename(path)+'.enc')
	encrypt_file(path, enc_file)
	sys.stdout.write("\t\tencrypted\n") if os.path.exists(enc_file) else sys.exit("[error] encryption %s does not exist" % enc_file)
	return os.stat(enc_file)[8], enc_file


def download_file(path, target):
	sys.stdout.write("[cloud] change detected: %s ..." % path)
	real_file = os.path.join(target, os.path.basename(path).replace('.enc', ''))
	decrypt_file(path, real_file)
	sys.stdout.write("\t\tdecrypted\n") if os.path.exists(real_file) else sys.exit("[error] decryption %s does not exist" % real_file)
	return os.stat(real_file)[8], real_file



def remove_cloud(path, target):
	sys.stdout.write("[local] file removed: %s ..." % path)
	enc_file = os.path.join(target, os.path.basename(path)+'.enc')
	os.remove(enc_file) if os.path.exists(enc_file) else None
	sys.stdout.write("\t\tdeleted\n")
	return enc_file


def remove_local(path, target):
	sys.stdout.write("[cloud] file removed: %s ..." % path)
	real_file = os.path.join(target, os.path.basename(path).replace('.enc', ''))
	os.remove(real_file) if os.path.exists(real_file) else None
	sys.stdout.write("\t\tdeleted\n")
	return real_file


def watch_dir(dest, target, local, database, file_function):
	side = 'local' if local else 'cloud'
	other_side = 'cloud' if local else 'local'
	files = os.listdir(dest)
	for file in files:
		path = os.path.join(dest, file)
		if os.path.isfile(path):
			moddate = os.stat(path)[8]
			if not path in database[side]:
				other_moddate, other_path = file_function(path, target)
				database[side][path] = dict()
				database[side][path]['moddate'] = moddate
				database[other_side][other_path] = dict()
				database[other_side][other_path]['moddate'] = other_moddate
			if moddate != database[side][path]['moddate']:
				other_moddate, other_path = file_function(path, target)
				database[side][path]['moddate'] = moddate
				database[other_side][other_path] = dict()
				database[other_side][other_path]['moddate'] = other_moddate
	deleted_files = set(database[side].keys()) - set(map(lambda x: os.path.join(dest, x), files))
	for deleted_file in deleted_files:
		if local:
			other_path = remove_cloud(deleted_file, target)
		else:
			other_path = remove_local(deleted_file, target)
		database[side].pop(deleted_file, None)
		database[other_side].pop(other_path, None)

	return database


def watch_local(dest, target, database):
	return watch_dir(dest, target, True, database, upload_file)

def watch_cloud(target, dest, database):
	return watch_dir(dest, target, False, database, download_file)


def run(argv):
	if len(argv) >= 5:
		local_directory = argv[1]
		cloud_directory = argv[2]
		database_path = argv[3]
	else:
		sys.exit('Usage: %s local_directory cloud_directory database_path password' % argv[0])

	if not os.path.exists(database_path):
		print('creating database at %s ...' % database_path)
		database = dict()
		database['local'] = dict()
		database['cloud'] = dict()
		update_db(database, database_path)		
	
	database = load_db(database_path)
	if type(database) == dict and 'local' in database and 'cloud' in database:
		while True:
			for watch in [watch_local, watch_cloud]:
				new_database = watch(local_directory, cloud_directory, copy.deepcopy(database))
				if new_database != database:
					update_db(new_database, database_path)
					database = new_database
			time.sleep(5)
	else:
		sys.exit('Error: corrupt database file %s' % database_path)


if __name__ == '__main__':
	print(sys.argv)
	PASSWORD = sys.argv[4].encode('utf-8')
	try:
		run(sys.argv)
	except KeyboardInterrupt:
		sys.exit("Good bye!\n")

