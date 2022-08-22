import re
import random
import datetime
import shutil
import os

filepath = os.path.abspath("shortsavedsearches.conf")
#looks through provided technology field for text you list.
input_providing_technologies = "Amazon Web Services"
# searches through rule name for words you don't want in use in your enviroment like GSuite or Amazon
input_rule = "GSuite Amazon"
# Enable Rule
enable_rule = True
#local saved search file
local_savedsearches = os.path.abspath(".\local\savedsearches.conf")


input_rule = input_rule.split()
# set up reg expresstion for parsing conf file
rule = re.compile(r'(^\[.+)')
providing_technologies = re.compile(r'(action\.escu\.providing_technologies).+')
confidence = re.compile(r'(action\.escu\.confidence).+')
cron_schedule = re.compile(r'(cron_schedule).+')
modification_date = re.compile(r'(action\.escu\.modification_date).+')
splunk_search = re.compile(r'(search =).+')

def backup_file(local_savedsearches):
    shutil.copyfile(local_savedsearches,local_savedsearches + ".bk")
backup_file(local_savedsearches)
def split_on_empty_lines(s):

    # greedily match 2 or more new-lines
    blank_line_regex = r"(?:\r?\n){2,}"

    return re.split(blank_line_regex, s.strip())
def parse_local_savedsearches(local_savedsearches):
    local_data = []
    with open(local_savedsearches, "r") as local_file_object:
        local_readfile = local_file_object.read()
        local_readfile = split_on_empty_lines(local_readfile)
        local_file_object.close()
        #backup local saved searches
        #localsavedsearches = open(".\local\savedsearches.conf.bk", "w")      
       
        for local_ruleset in local_readfile:
            for line in local_ruleset.splitlines():
                #localsavedsearches.writelines(line + "\n")
                if rule.match(line):
                    local_data.append(line + "\n")
                # for keeping track of modification date of rule
                if modification_date.match(line):
                    local_data.append(line + "\n")
        #localsavedsearches.close()
    return local_data
local_data = parse_local_savedsearches(local_savedsearches)        

def parse_file(filepath):
    data = []  # create an empty list to collect the data
    # open the file and read through it line by line
    with open(filepath, 'r') as file_object:
        readfile = file_object.read()
        readfile = split_on_empty_lines(readfile)
        file_object.close()

        for ruleset in readfile:
            # # at each line check for a match with a regex
            keep_data = False
            keep_data_rule = False
            tempdata = []
            confidence_data = []
            localrule = False
            update_search = False

            for line in ruleset.splitlines():
            # extract rule name and look for terms in the input_test variable
                for localline in local_data:
                    if rule.match(line):
                        tempdata.append(line + "\n")
                        for input_test in input_rule:
                            if input_test not in line:
                                keep_data_rule = True
                        # Enables the correlation search if set
                        if enable_rule == True:                                
                            tempdata.append("action.correlationsearch.annotations = {}\n")
                            tempdata.append("action.correlationsearch.enabled = 1\n")
                            tempdata.append("action.correlationsearch.label = " + (line.split("[")[1]).split("]")[0] + "\n")
                        if rule.match(localline):
                            if line == localline:
                                localrule = True    
                    # for fidelity matching on rule search
                    if confidence.match(line):
                        confidence_data = line.split("action.escu.confidence = ")[1]
                    # for keeping track of modification date of rule
                    if modification_date.match(line):
                        if localrule == True:
                            if modification_date.match(localline):
                                if datetime.datetime(line.split(" = ")[1]) > datetime.datetime(localline.split(" = ")[1]):
                                    update_search = True
                        tempdata.append(line + "\n")
                    # If you don't have the provided technology it won't be on this list
                    if providing_technologies.match(line):
                        if input_providing_technologies not in line:
                            keep_data = True
                    # random con so every hour at some random time it will run that way it's not all 0
                    if cron_schedule.match(line):
                        tempdata.append('cron_schedule = ' + str(random.randrange(1,59)) + ' * * * *\n')
                    # based on confidence of rule add eval statment to search. Take off eval if you aren't doing using it
                    if splunk_search.match(line):
                        if update_search == True:
                            if confidence_data == "high":
                                tempdata.append(line + " | eval fidelity=high ```This alert has a LOW chance of being a false positive```\n")
                            if confidence_data == "medium":
                                tempdata.append(line + " | eval fidelity=medium ```This alert has a chance of being a false positive```\n")
                            if confidence_data == "low":
                                tempdata.append(line + " | eval fidelity=low ```This alert has a HIGH chance of being a false positive```\n")
            if keep_data == True and keep_data_rule == True:
                data.append(tempdata)
                data.append("\n")

    return data
data = parse_file(filepath)
localsavedsearches = open(".\local\savedsearches.conf", "w")
for line in data:
    localsavedsearches.writelines(line)
localsavedsearches.close()
# https://www.vipinajayakumar.com/parsing-text-with-python/
