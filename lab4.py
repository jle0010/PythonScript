#! /usr/bin/env python
import pygeoip
number_of_IPs=0
addresses={}
file = open("logins.txt","r")
for line in file:
	split=line.split()
	IPs= split[2]
	if IPs in addresses:
		addresses[IPs]= addresses[IPs] + 1
	else:
        	addresses[IPs] = 1
			number_of_IPs= number_of_IPs + 1
print ("Question 1: There are {} unique addresses are in the file.".format(number_of_IPs), "\n")
print ("Question 2: How many times is each unique IP address present?", "\n")
print ("{:24s} {:5s}".format('IP Address:', 'Number of Occurences:'), "\n")
for IP,Number in addresses.items():
	print  ("{:20s} {:5d}".format(IP,Number))


def country():
	number_of_countries = {}
	locate = pygeoip.GeoIP('GeoIP.dat')
	print "\n","Question 3: What is the country of origin of each unique IP address?", "\n"
	print "{:25s} {:5s}".format('IP Address:', 'Country of Origin:')
	for IPs, count in addresses.items():
		countries = locate.country_name_by_addr(IPs)
		if countries in number_of_countries:
        		number_of_countries[countries] = number_of_countries[countries]+1
    		else:
        		number_of_countries[countries] = 1
		print "{:25s} {:5s}".format(IPs, countries)
	
	print "\n","Question 4: How many unique IP addresses are associated with each country?", "\n"
		
	for countries,count in number_of_countries.items():
    		countries = countries
		print  "{:25s} {:5d}".format(countries, count)
	
country()


