#!/usr/local/bin/python3
# This script downloads data from a MISP instance and writes them into a file

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert

misp_tags=['rsit:fraud="phishing"','tlp:green']
misp_type_attribute='url'
misp_last="14d"
phishing_url_file="phishing_urls.txt"

# Initialize connection to MISP instance
def init(url, key):
	return PyMISP(url, key, misp_verifycert, 'json')
      
# Get the specified data
def get_urls(m):
	unique_urls = set()
	
	result = m.search(last=misp_last, tags=misp_tags, type_attribute=misp_type_attribute)
   
	for e in result['response']:
		event_attributes= e.get('Event').get('Attribute')
		for a in event_attributes:
			unique_urls.add(a.get('value'))
	return unique_urls
	
# Write the data to a file
def write_urls_to_file(unique_urls):
	with open(phishing_url_file, "w") as the_file:
		for u in unique_urls:
			the_file.write(u + '\n')
	print('Wrote ' + str(len(unique_urls)) + ' URLs.')
							
# main routine
if __name__ == '__main__':
   
    print('\n--- This script downloads data with the following parameters:')
    print('MISP URL = ' + misp_url)
    print('MISP KEY = ' + misp_key)
    print('\nMISP TAGS = ' + str(misp_tags))
    print('MISP type attributes = ' + misp_type_attribute)
    print('Search the last ' + misp_last)
    print('\nThe data are written to the following file: ' + phishing_url_file)
	
    # Initialize connection to MISP instance
    misp = init(misp_url, misp_key)

    # Get the specified data
    unique_urls = get_urls(misp)
    
    # Write the data to a file
    write_urls_to_file(unique_urls)