from os import listdir
from os.path import isfile, join
from typing import KeysView
from pandas.core.frame import DataFrame
import requests
import re
import json
import zipfile
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

#python 3.9.5
#And seaborn library (includes matplotlib) for graphs 


def get_nvd_data():
	r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
	for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip",r.text):
		print(filename)
		r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
		with open("zip/" + filename, 'wb') as f:

			for chunk in r_file:
				f.write(chunk)


#get_nvd_data()


def unzip_data():
	files = [f for f in listdir("zip/") if isfile(join("zip/", f))]
	files.sort()
	for file in files:
		print("Opening: " + file)
		archive = zipfile.ZipFile(join("zip/", file), 'r')
		with archive as f:
			f.extractall('json')

#unzip_data()


def create_nvd_dict(year):
    filename = join("json/nvdcve-1.1-" + str(year) + ".json")
    #print("Opening: " + filename)
    with open(filename, encoding="utf8") as json_file:
    	cve_dict = json.load(json_file)
    return(cve_dict)

def contains_word(s, w):
	search_regex = f"\W{w}\W"
	regex = re.compile(search_regex, re.IGNORECASE)
	return regex.search(s) is not None

def contains_word_teacher(s, w):
	return (' ' + w.lower() + ' ') in (' ' + s.lower() + ' ')

def countCVE():
	# Get number of json files
	list = listdir("json/")
	number_files = len(list)
	dict_of_reports = {}
	#Considering CVE reports start from 2002 and there are as many files as reporting years
	for year in range(2002,2002 + number_files):
		year_in_string = str(year)
		dict_of_reports[year_in_string] = []
		cve_dict = create_nvd_dict(year)
		CVE_Items = cve_dict['CVE_Items']
		for item in CVE_Items:
			description_list = item['cve']['CVE_data_meta']
			if description_list:
				description = description_list['ID']
				if year_in_string in description:
					dict_of_reports[year_in_string].append(description)
	return (dict_of_reports)


def resultsByYear(expression):
	# Get number of json files
	list = listdir("json/")
	number_files = len(list)
	dict_of_reports = {}
	#Considering CVE reports start from 2002 and there are as many files as reporting years
	for year in range(2002,2002 + number_files):
		year_in_string = str(year)
		dict_of_reports[year_in_string] = []
		cve_dict = create_nvd_dict(year)
		CVE_Items = cve_dict['CVE_Items']
		for item in CVE_Items:
			description_list = item['cve']['description']['description_data']
			if description_list:
				description = description_list[0]['value']
				if contains_word(description, expression):
					dict_of_reports[year_in_string].append(item['cve']['CVE_data_meta']['ID'])

	#print (dict_of_reports)
	return (dict_of_reports)

def search_description(expression):
# Get number of json files
	list = listdir("json/")
	number_files = len(list)
	list_of_reports = []
	#Considering CVE reports start from 2002 and there are as many files as reporting years
	for year in range(2002,2002 + number_files):
		cve_dict = create_nvd_dict(year)
		CVE_Items = cve_dict['CVE_Items']
		for item in CVE_Items:
			description_list = item['cve']['description']['description_data']
			if description_list:
				description = description_list[0]['value']
				if contains_word(description, expression):
					list_of_reports.append(item['cve']['CVE_data_meta']['ID'])
	return (list_of_reports)

def averageScoreBySearch(expression):
	# Get number of json files
	list = listdir("json/")
	number_files = len(list)
	list_of_reports = []
	#Considering CVE reports start from 2002 and there are as many files as reporting years
	for year in range(2002,2002 + number_files):
		cve_dict = create_nvd_dict(year)
		CVE_Items = cve_dict['CVE_Items']
		for item in CVE_Items:
			description_list = item['cve']['description']['description_data']
			if description_list:
				description = description_list[0]['value']
				if contains_word(description, expression):
					try:
						list_of_reports.append(item['impact']['baseMetricV2']['cvssV2']['baseScore'])
					except KeyError:
						print ('exception: keyerror')
	return (list_of_reports)


def contains_ID(s, w):
	return ('' + w.lower() + '') in ('' + s.lower() + '')

def search_for_CWE(expression):
# Get number of json files
	list = listdir("json/")
	number_files = len(list)
	CWE = []
	#Considering CVE reports start from 2002 and there are as many files as reporting years
	for year in range(2002,2002 + number_files):
		cve_dict = create_nvd_dict(year)
		CVE_Items = cve_dict['CVE_Items']
		for item in CVE_Items:
			description_list = item['cve']['CVE_data_meta']
			if description_list:
				description = description_list['ID']
				if contains_ID(description, expression):
					CWE.append(item['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'])

	return (CWE)



def search_multiple_description(static_search, *args):
# Get number of json files
	list = listdir("json/")
	number_files = len(list)
	list_of_reports = {}
	#Considering CVE reports start from 2002 and there are as many files as reporting years
	for year in range(2002,2002 + number_files):
		cve_dict = create_nvd_dict(year)
		CVE_Items = cve_dict['CVE_Items']
		for item in CVE_Items:
			description_list = item['cve']['description']['description_data']
			if description_list:
				description = description_list[0]['value']
				for arg in args:
					if not arg in list_of_reports:
						list_of_reports[arg] = 0
					if contains_word(description, static_search) and contains_word(description, arg):
						list_of_reports[arg] += 1
	return (list_of_reports)


def ID_checkup():
	id_checkup1 = search_for_CWE('CVE-2018-10603')
	print ('checkup 1 done')
	id_checkup2 = search_for_CWE('CVE-2019-10936')
	print ('checkup 2 done')
	id_checkup3 = search_for_CWE('CVE-2019-10406')
	print ('checkup 3 done')

	print ('CWE1:' + str(id_checkup1))
	print ('CWE2:' + str(id_checkup2))
	print ('CWE3:' + str(id_checkup3))




def VulnerabilitiesPerYear():
	numberCVE = countCVE()

	graph_numbers = []
	graph_text = []

	for k, v in numberCVE.items():
		graph_text.append(k[-2:]) #tar sista 2 bokstäverna ur året
		graph_numbers.append(len(v)) # Lägger in length för det året

	print ("Total reported CVE incidents:" + str (graph_numbers))

	cvePlot = sns.barplot(y=graph_numbers, x=graph_text)
	cvePlot.set(xlabel='Year 20xx', ylabel='Incident Reports')
	cvePlot.set_title('Scale of Reported Vulnerabilities By Year')
	plt.show()



def avgcvssV2Score():
	list_of_RTU_score = averageScoreBySearch("RTU")
	#print ("rtu list:" + str (list_of_RTU_score))
	print ("rtu leng: " + str (len(list_of_RTU_score)))
	list_of_RTU = search_description("RTU")

	list_of_PLC_score = averageScoreBySearch("PLC")
	#print ("plc list:" + str (list_of_PLC_score))
	print ("plc leng: " + str (len(list_of_PLC_score)))
	list_of_PLC = search_description("PLC")

	list_of_HMI_score = averageScoreBySearch("HMI")
	#print ("hmi list:" + str (list_of_HMI_score))
	print ("hmi leng: " + str (len(list_of_HMI_score)))
	list_of_HMI = search_description("HMI")

	list_of_MTU_score = averageScoreBySearch("MTU")
	#print ("mtu list:" + str (list_of_MTU_score))
	print ("mtu lengh: " + str (len(list_of_MTU_score)))
	list_of_MTU = search_description("MTU")


	print ('Average RTU cvssV2 score: ' + str (np.average(list_of_RTU_score)))
	print ("RTU search hits: " + str (len(list_of_RTU)))
	print ('Average PLC cvssV2 score: ' + str (np.average(list_of_PLC_score)))
	print ("PLC search hits: " + str (len(list_of_PLC)))
	print ('Average HMI cvssV2 score: ' + str (np.average(list_of_HMI_score)))
	print ("HMI search hits: " + str (len(list_of_HMI)))
	print ('Average MTU cvssV2 score: ' + str (np.average(list_of_MTU_score)))
	print ("MTU search hits: " + str (len(list_of_MTU)))




def ReportedThreatsByYear():
	values_for_graph = []
	list_of_Overflow_IDs = search_description("overflow")
	values_for_graph.append(len(list_of_Overflow_IDs))
	print ('overflow done')

	list_of_denial_of_service_IDs = search_description("denial of service")
	values_for_graph.append(len(list_of_denial_of_service_IDs))
	print ('denial of service done')

	list_of_SQL_Injection_IDs = search_description("sql injection")
	values_for_graph.append(len(list_of_SQL_Injection_IDs))
	print ('sql injection done')

	list_of_Cross_Site_IDs = search_description("cross-site")
	values_for_graph.append(len(list_of_Cross_Site_IDs))
	print ('cross-site done')

	list_of_Memory_Corruption_IDs = search_description("memory corruption")
	values_for_graph.append(len(list_of_Memory_Corruption_IDs))
	print ('memory corruption done')

	print ("Number of overflow related reports:" + str (len(list_of_Overflow_IDs)))
	print ("Number of denial of service related reports:" + str (len(list_of_denial_of_service_IDs)))
	print ("Number of sql injection related reports:" + str (len(list_of_SQL_Injection_IDs)))
	print ("Number of cross-site related reports:" + str (len(list_of_Cross_Site_IDs)))
	print ("Number of memory corruption related reports:" + str (len(list_of_Memory_Corruption_IDs)))
	print ("error types:" + str (values_for_graph))

	graph_text = ['overflow', 'dos', 'sql inject', 'cross-site', 'memory corr']
	Vulnerabilities = sns.barplot(y=values_for_graph, x=graph_text)
	Vulnerabilities.set(xlabel='Year 20xx', ylabel='Incident Reports')
	Vulnerabilities.set_title('Scale of Reported Threats By Year')

	plt.show()


#task 3.1
print ('task 3.1a')
ID_checkup()
print ('task 3.1b')
VulnerabilitiesPerYear()

#task 4.1
print ('task 4.1')
ReportedThreatsByYear()

print ('done')
