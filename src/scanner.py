#!/bin/python3

import sys
import socket
from datetime import datetime as dt
import _thread
import time
from threading import Thread
import os.path
import pyfiglet

open_port_count = 0
start_port = 0
end_port = 1001
rep_fileName = "ip_report.txt"
replace_existing_file = "N"
output_file = open(rep_fileName, "a+")

open_port_data = ""

max_port = 65535
bann_width = 80


def bann(): #Def a Function for adding any banners
	return ("*" * bann_width) + "\n" + ("{0}{1}{0}".format(" " * ((bann_width-20)//2), "-" * (bann_width - (bann_width-20)))) + "\n" + ("*" * bann_width)


def simp_bann():
	print("*" * bann_width)

def align_text(text):
	return " " * ((bann_width - len(text))//2) + text

	
def check_port_for_target(target, port):
	try:
		global open_port_count, open_port_data
		conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		socket.setdefaulttimeout(1)
		result = conn.connect_ex((target,port)) #returns an error indicator
		if result == 0:
			open_port_data += "Port {} is open.\n".format(port)
			print("Port {} is open.".format(port))
			open_port_count += 1
		conn.close()
	except KeyboardInterrupt:
		print("\nExiting Program...")
		sys.exit()
	except socket.gaierror:
		print("Hostname could not be resolved")
		sys.exit()
	except socket.error:
		print("Couldn't connect to server")
		sys.exit() 



print(pyfiglet.figlet_format("PORT SCANNER"))


#Define the target
if len(sys.argv) == 2:
	try:
		target = socket.gethostbyname(sys.argv[1]) #Translate hostname to an ipv4 address
	except Exception as e:
		print("Error Resolving the DNS for \"{}\"".format(sys.argv[1]))
		sys.exit()
elif len(sys.argv) == 3:
	try:
		target = socket.gethostbyname(sys.argv[1]) #Translate hostname to an ipv4 address
	except Exception as e:
		print("Error Resolving the DNS for \"{}\"".format(sys.argv[1]))
		sys.exit()
	try:
		max_port = int(sys.argv[2])
	except ValueError as e:
		print("Please Provide a Proper Port number \"{}\"".format(sys.argv[2]))
		sys.exit()
else:
	print("Invalid amount of arguments") 
	print("Syntax: python3 scanner.py <ip>")
	sys.exit()
	
	
print(bann())
print(align_text("Scanning Target " + target))
simp_bann()
print(align_text("Time Started " + str(dt.now())))
print(bann())

try:
	append_to_fileName = 0
	f_array = rep_fileName.split(".")
	while os.path.exists(rep_fileName) and replace_existing_file.upper()=="N":
		replace_existing_file = input("{} already Exists. Do you want to replace it? (Y/n) ".format(rep_fileName))
		if replace_existing_file.upper() == "N":
			append_to_fileName += 1
			rep_fileName = f_array[0] + str(append_to_fileName) + "." + f_array[1]
	else:
		#print("IN ELSE BLOCK")
		if replace_existing_file.upper() == "Y":
			os.remove(rep_fileName)
		output_file = open(rep_fileName, "a+")
	
	print("The Report Will Be Stored In The File {}".format(rep_fileName))
	
	
	output_file.write(pyfiglet.figlet_format("PORT SCANNER"))
	output_file.write( bann() + "\n")
	output_file.write(align_text("Port Scanning Reoport for {}".format(target) + "\n"))
	output_file.write(align_text("Time Started " + str(dt.now()) + "\n"))
	output_file.write( bann() + "\n")
	
	max_port += 1
	while max_port > end_port:
		for port in range(start_port, end_port):
			if(port%100 == 0 or port == (max_port - 1)):
				print("Checking Port {}".format(port))
			
			td = Thread(target = check_port_for_target, args=(target, port, ))
			td.daemon = True
			td.start()
		td.join()
		start_port = end_port
		end_port += 1000
	
	for port in range(start_port, max_port):
		if(port%100 == 0 or port == (max_port - 1)):
			print("Checking Port {}".format(port))
		#check_port_for_target(target, port)
		#fin = _thread.start_new_thread(check_port_for_target, (target, port, ))
		td1 = Thread(target = check_port_for_target, args=(target, port, ))
		td1.daemon = True
		td1.start()
	td1.join()
	
		
except KeyboardInterrupt:
	print("\nExiting Program...")
	output_file.write(open_port_data)
	output_file.write("Execution Interrupted. \n Exiting Program ..." + str(dt.now()))
	output_file.close()
	sys.exit()
except socket.gaierror:
	print("Hostname could not be resolved")
	output_file.write(open_port_data)
	output_file.close()
	output_file.write("Hostname could not be resolved\n Exiting Program ..." + str(dt.now()))
	sys.exit()
except socket.error:
	print("Couldn't connect to server")
	output_file.write(open_port_data)
	output_file.write("Couldn't connect to server\n Exiting Program ..." + str(dt.now()))
	output_file.close()
	sys.exit() 

#output_file = open(rep_fileName, "a+")
output_file.write(open_port_data)
output_file.write( bann() + "\n")
output_file.write(align_text("Program Execution Complete!\n"))
output_file.write("Total Number of Open Ports: {}\n".format(open_port_count))
output_file.write("End Time " + str(dt.now()) + "\n")
output_file.write( bann() + "\n")
output_file.close()
print(bann())
print(align_text("Program Execution Complete!"))
print(bann())
sys.exit(1)
print(bann())
