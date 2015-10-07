#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  test.py
#  
#  Copyright 2015 Grant <gsims@ubuntu>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

#importing modules
import csv
import argparse

#take in commandline arguments
parser = argparse.ArgumentParser(description='This is a Snort DSS Import to Bro_Intel for SecurityOnion')
parser.add_argument('-f', '--file', help='Input CVS file from DSS', required=True)
args = parser.parse_args()


#prints out programs initial ASCII Art, whats my first python program without ascii art!
def GS_ascii():
	GS_art = """
  ____  ____ ____        _              ____               ___       _       _ 
 |  _ \/ ___/ ___|      | |_ ___       | __ ) _ __ ___    |_ _|_ __ | |_ ___| |
 | | | \___ \___ \ _____| __/ _ \ _____|  _ \| '__/ _ \    | || '_ \| __/ _ \ |
 | |_| |___) |__) |_____| || (_) |_____| |_) | | | (_) |   | || | | | ||  __/ |
 |____/|____/____/       \__\___/      |____/|_|  \___/___|___|_| |_|\__\___|_|
                                                     |_____|                   
	"""
	print GS_art

#function to open csvfile
def opencsv(csvfile):
	
	#open file and store contents in variable
	f = open(args.file)
	csv_f = csv.reader(f)
	return csv_f
	
#function to print csv contents
def printcsv(csvfile):
	
	for row in csvfile:
		print row
		
#function to pull out 'type' 'MD5' from DSS IOCs
def onlymd5(csvfile):
	
	md5list = []
	
	for row in csvfile:
		if row[1] == 'MD5':
			md5list.append(row[0])
	
	return md5list
	
#function to pull out 'type' 'IPV4ADDR' from DSS IOCs
def onlyipv4(csvfile):
	
	ipv4list = []
	
	for row in csvfile:
		if row[1] == 'IPV4ADDR':
			ipv4list.append(row[0])
	
	return ipv4list
	
#function to pull out 'type' 'FQDN' from DSS IOCs
def onlyfqdn(csvfile):
	
	fqdnlist = []
	
	for row in csvfile:
		if row[1] == 'FQDN':
			fqdnlist.append(row[0])
	
	return fqdnlist
	
	
#function to take MD5, IPV4ADDR lists and put into bro_intel format
def liststobrointel(md5list, ipv4list, fqdnlist):
	
	filedescription = raw_input('\nPlease enter a description for all of the Bro_Intel entries (ex. DSS-CI-CTA-0016015) \nDescription: ')
	print("\nCopy and paste the following into your Intel.dat file... \n")
	for md5s in md5list:
		print(md5s + "\tIntel::FILE_HASH\t" + filedescription + "\tT")
	for ipv4s in ipv4list:
		print(ipv4s + "\tIntel::ADDR\t" + filedescription + "\tT")
	for fqdns in fqdnlist:
		print(fqdns + "\tIntel::DOMAIN\t" + filedescription + "\tT")
	print("\n")

def main():
	
	GS_ascii()
	
	print("Welcome, This program will Parse your DSS CSV file into the Bro_Intel format")
	print("\nThe program supports the following Bro_Intel indicators: \nIntel:ADDR \nIntel:DOMAIN \nIntel:FILE_HASH ")
	print("\nThe DSS file you are importing is:\"" + args.file + "\"")
	
	#open the CSV and pull out just the MD5s from the DSS IOC
	openedcsv = opencsv(args.file)
	md5list = onlymd5(openedcsv)
	#print(md5list)
	
	#open the CSV and pull out just the IPV4ADDR from the DSS IOC
	openedcsv = opencsv(args.file)
	ipv4list = onlyipv4(openedcsv)
	#print(ipv4list)
	
	#open the CSV and pull out just the FQDN from the DSS IOC
	openedcsv = opencsv(args.file)
	fqdnlist = onlyfqdn(openedcsv)
	#print(fqdnlist)
	
	#output of all list to Bro_Intel format
	liststobrointel(md5list, ipv4list, fqdnlist)
	
	
	
	
	
	return 0

if __name__ == '__main__':
	main()

