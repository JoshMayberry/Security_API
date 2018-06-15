__version__ = "1.0.0"

#Import standard elements
import warnings
import subprocess

#Import communication elements for talking to other devices such as printers, the internet, a raspberry pi, etc.
import usb
import select
import socket
import serial
import netaddr
import serial.tools.list_ports

#Import barcode software for drawing and decoding barcodes
import qrcode
import barcode

#Required Modules
##py -m pip install
	# pyserial
	# netaddr
	# pyusb
	# pyBarcode
	# qrcode

##Module dependancies (Install the following .exe and/or .dll files)
	#"Ghostscript AGPL Release" on "https://ghostscript.com/download/gsdnld.html"
		#Make sure you install the 32 bit version if you are using 32 bit python
		#Add the .dll location to your PATH enviroment variable. Mine was at "C:\Program Files (x86)\gs\gs9.20\bin"

	#The latest Windows binary on "https://sourceforge.net/projects/libusb/files/libusb-1.0/libusb-1.0.21/libusb-1.0.21.7z/download"
		#If on 64-bit Windows, copy "MS64\dll\libusb-1.0.dll" into "C:\windows\system32"
		#If on 32-bit windows, copy "MS32\dll\libusb-1.0.dll" into "C:\windows\SysWOW64"

#User Access Variables
ethernetError = socket.error

#Controllers
def build(*args, **kwargs):
	"""Starts the GUI making process."""

	return Security(*args, **kwargs)

class Security():
	"""Allows the user to encrypt and decrypt files.
	Adapted from: http://www.blog.pythonlibrary.org/2016/05/18/python-3-an-intro-to-encryption/
	"""

	def __init__(self):
		"""Initializes defaults and internal variables."""

		#Defaults
		self.password = "Admin"

		#Internal Variables
		self.missingPublicKey  = True
		self.missingPrivateKey = True

	def setPassword(self, password):
		"""Changes the encryption password.

		password (str) - What the encryption password is

		Example Input: setPassword("Lorem")
		"""

		self.password = password

	def generateKeys(self, privateDir = "", publicDir = "", privateName = "privateKey", publicName = "publicKey", autoLoad = True):
		"""Creates a private and public key.

		privateDir (str)  - The save directory for the private key
		publicDir (str)   - The save directory for the public key
		privateName (str) - The name of the private key file
		publicName (str)  - The name of the public key file
		autoLoad (bool)   - Automatically loads the generated keys into memory

		Example Input: generateKeys()
		Example Input: generateKeys(autoLoad = False)
		"""

		#Create the key
		key = Cryptodome.PublicKey.RSA.generate(2048)
		encryptedKey = key.exportKey(passphrase = self.password, pkcs=8, protection = "scryptAndAES128-CBC")

		#Save the key
		with open(privateDir + privateName + ".pem", 'wb') as fileHandle:
				fileHandle.write(encryptedKey)

		with open(publicDir + publicName + ".pem", 'wb') as fileHandle:
				fileHandle.write(key.publickey().exportKey())

		#Load the key
		if (autoLoad):
			self.loadKeys(privateDir, publicDir, privateName, publicName)

	def loadKeys(self, privateDir = "", publicDir = "", privateName = "privateKey", publicName = "publicKey"):
		"""Creates a private and public key.

		privateDir (str)  - The save directory for the private key
		publicDir (str)   - The save directory for the public key
		privateName (str) - The name of the private key file
		publicName (str)  - The name of the public key file

		Example Input: loadKeys()
		"""

		self.loadPrivateKey(privateDir, privateName)
		self.loadPublicKey(publicDir, publicName)

	def loadPrivateKey(self, directory = "", name = "privateKey"):
		"""Loads the private key into memory.

		directory (str) - The save directory for the private key
		name (str)      - The name of the private key file

		Example Input: loadPrivateKey()
		"""

		self.privateKey = Cryptodome.PublicKey.RSA.import_key(
			open(directory + name + ".pem").read(), passphrase = self.password)

		self.missingPrivateKey = False

	def loadPublicKey(self, directory = "", name = "publicKey"):
		"""Loads the public key into memory.

		directory (str) - The save directory for the public key
		name (str)      - The name of the public key file

		Example Input: loadPublicKey()
		"""

		self.publicKey = Cryptodome.PublicKey.RSA.import_key(
			open(directory + name + ".pem").read())

		self.missingPublicKey = False

	def encryptData(self, data, directory = "", name = "encryptedData", extension = "db"):
		"""Encrypts a string of data to a new file.
		If a file by the same name already exists, it replaces the file.

		data (str)      - The string to encrypt and store
		directory (str) - The save directory for the encrypted data
		name (str)      - The name of the encrypted data
		extension (str) - The file extension for the encrypted data

		Example Input: encryptData("Lorem Ipsum")
		Example Input: encryptData("Lorem Ipsum", extension = "txt")
		"""

		#Check for keys
		if (self.missingPublicKey or self.missingPrivateKey):
			warnings.warn(f"Cannot encrypt data without keys for {self.__repr__()}\n Use 'loadKeys()' or 'loadPublicKey() and loadPrivateKey()' first", Warning, stacklevel = 2)
			return None

		#Format the output path
		outputName = f"{directory}{name}.{extension}"

		#Format the data
		data = data.encode("utf-8")

		#Create the file
		with open(outputName, "wb") as outputFile:
			sessionKey = Cryptodome.Random.get_random_bytes(16)

			#Write the session key
			cipherRSA = Cryptodome.Cipher.PKCS1_OAEP.new(self.publicKey)
			outputFile.write(cipherRSA.encrypt(sessionKey))

			#Write the data
			cipherAES = Cryptodome.Cipher.AES.new(sessionKey, Cryptodome.Cipher.AES.MODE_EAX)
			ciphertext, tag = cipherAES.encrypt_and_digest(data)

			outputFile.write(cipherAES.nonce)
			outputFile.write(tag)
			outputFile.write(ciphertext)

	def decryptData(self, directory = "", name = "encryptedData", extension = "db"):
		"""Decrypts an encrypted file into a string of data

		directory (str) - The save directory for the encrypted data
		name (str)      - The name of the encrypted data
		extension (str) - The file extension for the encrypted data

		Example Input: encryptData()
		Example Input: encryptData(extension = "txt")
		"""

		#Check for keys
		if (self.missingPublicKey or self.missingPrivateKey):
			warnings.warn(f"Cannot decrypt data without keys for {self.__repr__()}\n Use 'loadKeys()' or 'loadPublicKey() and loadPrivateKey()' first", Warning, stacklevel = 2)
			return None

		#Format the output path
		inputName = f"{directory}{name}.{extension}"

		#Create the file
		with open(inputName, "rb") as inputFile:
			endSessionKey, nonce, tag, ciphertext = [ inputFile.read(x) 
			for x in (self.privateKey.size_in_bytes(), 16, 16, -1) ]

			cipherRSA = Cryptodome.Cipher.PKCS1_OAEP.new(self.privateKey)
			sessionKey = cipherRSA.decrypt(endSessionKey)

			cipherAES = Cryptodome.Cipher.AES.new(sessionKey, Cryptodome.Cipher.AES.MODE_EAX, nonce)
			data = cipherAES.decrypt_and_verify(ciphertext, tag)                

		#Format the output data
		data = data.decode("utf-8")
		return data