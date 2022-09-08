#Created by CWObuzz https://github.com/cwobuzz
#Please use the readme file found at https://github.com/cwobuzz/Splunk-savededsearchreader
print("This script needs the filepath to your default and local savedsearches.conf file.\n Set your filters for what you want to keep: filter_list_for_rule_name")

import re
import random
import datetime
import shutil
import os

#path to your default savedsearches.conf file
default_savedsearchesconf = os.path.abspath("./dist/ESCU_Alerts/default/savedsearches.conf")
#local saved search file
local_savedsearches = os.path.abspath("./dist/ESCU_Alerts/local/savedsearches.conf")
# searches through rule name for words you don't want in use in your enviroment like GSuite or Amazon
filter_list_for_rule_name = ["Amazon", "Gsuite", "GSuite ", "AWS", " aws ", "EC2", "GCP", " gcp ", "Okta"]
# Remove any providing technologies only put over all name like Amazon, not Amazon Web Services
input_providing_technologies = "Amazon"
# Enable Rule sets the action.escu, action.escu.enabled, action.risk, action.correlationsearch.enabled, enableSched all to 1
enable_rule = True

#filter_list_for_rule_name = filter_list_for_rule_name.split()
# set up reg expresstion for parsing conf file
rule = re.compile(r'(^\[.+)')
providing_technologies = re.compile(r'(action\.escu\.providing_technologies).+')
confidence = re.compile(r'(action\.escu\.confidence).+')
cron_schedule = re.compile(r'(cron_schedule).+')
modification_date = re.compile(r'(action\.escu\.modification_date).+')
search_type = re.compile(r'(action\.escu\.search_type).+')
splunk_search = re.compile(r'(search =).+')
correlationsearch_annotations = re.compile(r'(action\.correlationsearch\.annotations).+')
correlationsearch_enabled = re.compile(r'(action\.correlationsearch\.enabled).+')
correlationsearch_label = re.compile(r'(action\.correlationsearch\.label).+')
action_escu = re.compile(r'(action\.escu =).+')
is_enabled = re.compile(r'(action\.escu\.enabled).+')
risk = re.compile(r'(action\.risk).+')
dispatch = re.compile(r'(dispatch\.).+')
schedule_window = re.compile(r'(schedule_window).+')
alert_digest_mode = re.compile(r'(alert\.digest_mode).+')
disabled = re.compile(r'(disabled).+')
enableSched = re.compile(r'(enableSched).+')
allow_skew = re.compile(r'(allow_skew).+')
counttype = re.compile(r'(counttype).+')
relation = re.compile(r'(relation).+')
quantity = re.compile(r'(quantity).+')
realtime_schedule = re.compile(r'(realtime_schedule).+')
is_visible = re.compile(r'(is_visible).+')

#Dictionary for data
Dict = {}

def backup_file(local_savedsearches):
    shutil.copyfile(local_savedsearches,local_savedsearches + ".bk")
backup_file(local_savedsearches)
def split_on_empty_lines(s):

    # greedily match 2 or more new-lines
    blank_line_regex = r"(?:\r?\n){2,}"

    return re.split(blank_line_regex, s.strip())
def parse_local_savedsearches(local_savedsearches):

    with open(local_savedsearches, "r") as local_file_object:
        local_readfile = local_file_object.read()
        local_readfile = split_on_empty_lines(local_readfile)
        local_file_object.close()
          
       
        for local_ruleset in local_readfile:
            for line in local_ruleset.splitlines():
                if rule.match(line):
                    Dict[line] = {}
                    Dict[line][line] = line
                    dic_rule = line
                    continue
                    #Dict[line][line] = line   
                if is_enabled.match(line):
                    Dict[dic_rule]['is_enabled'] = {line}
                    continue
                if action_escu.match(line):
                    Dict[dic_rule]['action_escu'] = {line}
                    continue
                if correlationsearch_annotations.match(line):
                    Dict[dic_rule]['correlationsearch_annotations'] = {line}
                    continue
                if correlationsearch_enabled.match(line):
                    Dict[dic_rule]['correlationsearch_enabled'] = {line}
                    continue
                if correlationsearch_label.match(line):
                    Dict[dic_rule]['correlationsearch_label'] = {line}
                    continue
                # for keeping track of modification date of rule
                if modification_date.match(line):
                    Dict[dic_rule]['modification'] = {line}
                    continue
                if search_type.match(line):
                    Dict[dic_rule]['search_type'] = {line}
                    continue
                if risk.match(line):
                    Dict[dic_rule]['risk'] = {line}
                    continue
                if cron_schedule.match(line):
                    Dict[dic_rule]['cron_schedule'] = {line}
                    continue
                if dispatch.match(line):
                    Dict[dic_rule]['dispatch'] = {line}
                    continue
                if schedule_window.match(line):
                    Dict[dic_rule]['schedule_window'] = {line}
                    continue
                if alert_digest_mode.match(line):
                    Dict[dic_rule]['alert_digest_mode'] = {line}
                    continue
                if disabled.match(line):
                    Dict[dic_rule]['disabled'] = {line}
                    continue
                if enableSched.match(line):
                    Dict[dic_rule]['enableSched'] = {line}
                    continue
                if allow_skew.match(line):
                    Dict[dic_rule]['allow_skew'] = {line}
                    continue
                if counttype.match(line):
                    Dict[dic_rule]['counttype'] = {line}
                    continue
                if relation.match(line):
                    Dict[dic_rule]['relation'] = {line}
                    continue
                if quantity.match(line):
                    Dict[dic_rule]['quantity'] = {line}
                    continue
                if realtime_schedule.match(line):
                    Dict[dic_rule]['realtime_schedule'] = {line}
                    continue
                if is_visible.match(line):
                    Dict[dic_rule]['is_visible'] = {line}
                    continue
                if splunk_search.match(line):
                    Dict[dic_rule]['splunk_search'] = {line}
                    continue
                else:
                    word = line.split(" = ")[0]
                    Dict[dic_rule][word] = {line}
        #localsavedsearches.close()
    return Dict
    
Dict = parse_local_savedsearches(local_savedsearches)        

def parse_file(default_savedsearchesconf):

    # open the file and read through it line by line
    with open(default_savedsearchesconf, 'r') as file_object:
        readfile = file_object.read()
        readfile = split_on_empty_lines(readfile)
        file_object.close()

        for ruleset in readfile:
            # # at each line check for a match with a regex
            keep_data_rule = False
            confidence_data = []
            localrule = False
            update_search = False
            search_type_NOT_detection = False

            for line in ruleset.splitlines():
            # extract rule name and look for terms in the input_test variable      
                if rule.match(line):
                    
                    if not any(value in line for value in filter_list_for_rule_name):    
                            keep_data_rule = True
                            
                    for key in Dict:
                        if line == str(key):
                            dic_rule = line
                            localrule = True
                            break
                                                        
                    if localrule != True: 
                        if keep_data_rule == True:
                            Dict[line] = {}    
                            Dict[line][line] = line
                            dic_rule = line       

                # makes sure the rules are enabled
                if action_escu.match(line):
                    if keep_data_rule == True:
                        if enable_rule == True:
                            Dict[dic_rule]['action_escu'] = "action.escu = 1"                      
                if is_enabled.match(line):
                    if keep_data_rule == True:
                        if enable_rule == True:
                            Dict[dic_rule]['is_enabled'] = "action.escu.enabled = 1"
                if risk.match(line):    
                    if keep_data_rule == True:
                        if enable_rule == True:
                            Dict[dic_rule]['risk'] = "action.risk = 1"
                if correlationsearch_enabled.match(line):
                    if keep_data_rule == True:
                        if enable_rule == True:
                            Dict[dic_rule]['correlationsearch_enabled'] = "action.correlationsearch.enabled = 1"
                if enableSched.match(line):
                    if keep_data_rule == True:
                        if enable_rule == True:
                            Dict[dic_rule]['enableSched'] = "enableSched = 1"
                # for fidelity matching on rule search
                if confidence.match(line):
                    if keep_data_rule == True:
                        confidence_data = line.split("action.escu.confidence = ")[1]
                    
                # for keeping track of modification date of rule
                if modification_date.match(line):
                    if keep_data_rule == True:
                        if localrule == True:
                            try:
                                if datetime.datetime.strptime(line.split(" = ")[1], '%Y-%m-%d').date() > datetime.datetime.strptime(str(Dict[dic_rule]['modification']).split(" = ")[1].split("\'")[0], '%Y-%m-%d').date():
                                    Dict[dic_rule]['modifcation'] = line
                                    update_search = True
                            except:
                                pass
                        elif keep_data_rule == True:
                            Dict[dic_rule]['modifcation'] = line
                
                if correlationsearch_label.match(line):
                    if re.search('Deprecated', line, re.IGNORECASE):
                        keep_data_rule = False

                # If you don't have the provided technology it won't be on this list
                if providing_technologies.match(line):
                     if not any(value in line for value in input_providing_technologies):
                        keep_data_rule = False
                        
                # random con so every hour at some random time it will run that way it's not all 0
                if cron_schedule.match(line):
                    if keep_data_rule == True:
                        Dict[dic_rule]['cron_schedule'] = 'cron_schedule = ' + str(random.randrange(1,59)) + ' * * * *'

                if search_type.match(line):
                    if line != "action.escu.search_type = detection":
                        search_type_NOT_detection = True
 
                # based on confidence of rule add eval statment to search. Take off eval if you aren't using it
                if splunk_search.match(line):
                    if update_search == True or (keep_data_rule == True and localrule == False):
                        if confidence_data == "high":
                            Dict[dic_rule]['splunk_search'] = line + " | eval fidelity=high ```This alert has a LOW chance of being a false positive```"
                         
                        if confidence_data == "medium":
                            Dict[dic_rule]['splunk_search'] = line + " | eval fidelity=medium ```This alert has a chance of being a false positive```"
                          
                        if confidence_data == "low":
                            Dict[dic_rule]['splunk_search'] = line + " | eval fidelity=low ```This alert has a HIGH chance of being a false positive```"

                try:
                    if search_type_NOT_detection == False:
                        if keep_data_rule == False:
                            Dict.pop(dic_rule)
                            # Rules that are disable 
                            Dict[dic_rule] = {}    
                            Dict[dic_rule][dic_rule] = dic_rule
                            Dict[dic_rule]['action_escu'] = "action.escu = 0"
                            Dict[dic_rule]['enable'] = "action.escu.enabled = 0"
                            Dict[dic_rule]['risk'] = "action.risk = 0"
                            Dict[dic_rule]['correlationsearch'] = "action.correlationsearch.enabled = 0"
                            Dict[dic_rule]['enableSched'] = "enableSched = 0"
                except:
                    pass
                
    return Dict
data = parse_file(default_savedsearchesconf)
localsavedsearches = open(local_savedsearches, "w")
def iterate_dict(data):
    for key, value in data.items():
        # print(key)
        for v in value:
            
            if re.split(r"^{'",str(value[v]))[0] == "": 
                if rule.match(v):
                    localsavedsearches.writelines("\n")
                    localsavedsearches.writelines((re.split(r"^{'|'}$",str(value[v]))[1]) + "\n")
                else:    
                    localsavedsearches.writelines((re.split(r"^{'|'}$",str(value[v]))[1]) + "\n")
            else:    
                if rule.match(v):
                    localsavedsearches.writelines("\n")
                    localsavedsearches.writelines(str(value[v]) + "\n")
                else:
                    localsavedsearches.writelines(str(value[v]) + "\n")
iterate_dict(data)  

localsavedsearches.close()

