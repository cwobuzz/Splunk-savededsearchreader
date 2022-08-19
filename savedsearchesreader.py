import re
import random

filepath = (r"savedsearches.conf")
#looks through provided technology field for text you list.
input_providing_technologies = "Amazon Web Services"
# searches through rule name for words you don't want in use in your enviroment like GSuite or Amazon
input_rule = "GSuite Amazon"

input_rule = input_rule.split()
# set up reg expresstion for parsing conf file
rule = re.compile(r'(^\[.+)')
providing_technologies = re.compile(r'(action\.escu\.providing_technologies).+')
confidence = re.compile(r'(action\.escu\.confidence).+')
cron_schedule = re.compile(r'(cron_schedule).+')
splunk_search = re.compile(r'(search =).+')

def split_on_empty_lines(s):

    # greedily match 2 or more new-lines
    blank_line_regex = r"(?:\r?\n){2,}"

    return re.split(blank_line_regex, s.strip())

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
            
            for line in ruleset.splitlines():
            # extract rule name and look for terms in the input_test variable
                if rule.match(line):
                    tempdata.append(line + "\n")
                    for input_test in input_rule:
                        if input_test not in line:
                            keep_data_rule = True
                # for fidelity matching on rule search
                if confidence.match(line):
                    confidence_data = line.split("action.escu.confidence = ")[1]
                # If you don't have the provided technology it won't be on this list
                if providing_technologies.match(line):
                    if input_providing_technologies not in line:
                        keep_data = True
                # random con so every hour at some random time it will run that way it's not all 0
                if cron_schedule.match(line):
                    tempdata.append('cron_schedule = ' + str(random.randrange(1,59)) + ' * * * *\n')
                # based on confidence of rule add eval statment to search. Take off eval if you aren't doing using it
                if splunk_search.match(line):
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
localsavedsearches = open(".\local\savedsearches.conf", "x")
for line in data:
    localsavedsearches.writelines(line)
localsavedsearches.close()
# https://www.vipinajayakumar.com/parsing-text-with-python/
