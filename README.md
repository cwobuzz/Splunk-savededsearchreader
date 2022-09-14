# Splunk-savededsearchreader
The savedsearchreader looks through local and default savedsearches.conf file of ESCU content. It modifies the local files. It will filter out values defined in the first 10 lines of the code. It will look for new modification dates and update your local file for the new search. It will look for deprecated and set those to not work. Please look through the code and change those variables as needed. To Do is test and make the variables switches.


This is to be used with https://github.com/splunk/security_content
This code list should get you started.
### For your first time do this:
```
  git clone git@github.com:splunk/security_content.git OR git clone https://github.com/splunk/security_content.git
  mkdir ~/src
  wget https://www.python.org/ftp/python/3.9.13/Python-3.9.13.tar.xz
  mv Python-3.9.13.tar.xz src/
  tar -xf ~/src/Python-3.9.13.tar.xz 
  cd Python-3.9.13/
  mkdir ~/.localpython
  ./configure --prefix=$HOME/.localpython
  make install
  ~/.localpython/bin/python setup.py install
  virtualenv venv -p $HOME/.localpython/bin/python3.9
  source venv/bin/activate
  cd security_content/
  pip install -r requirements.txt
  python contentctl.py -p . validate -pr ESCU
  python contentctl.py -p . generate -o dist/escu -pr ESCU
  python contentctl.py -p . init -t ESCU_Alerts -n ESCU_Alerts -v 1 -a "Your Name" -d "App built with security_content from github" -e my@email.com -c "My Company"
  mkdir dist/ESCU_Alerts/local
  touch dist/ESCU_Alerts/local/savedsearches.conf
  git clone https://github.com/cwobuzz/Splunk-savededsearchreader.git
  mv ./Splunk-savededsearchreader/savedsearchesreader.py .
  nano savedsearchesreader.py ##Change the filter_list_for_rule_name AND nput_providing_technologies variables to your needs!
  python savedsearchesreader.py
  cd dist
  tar -czvf ESCU_Alerts.tar.gz ESCU_Alerts/
```  
### If you have already ran the program
```
  cd .. ## out of your security_content folder
  git clone https://github.com/splunk/security_content.git tmp/
  cp -R tmp/ security_content/
  virtualenv venv -p $HOME/.localpython/bin/python3.9
  source venv/bin/activate
  cd security_content
  python contentctl.py -p . validate -pr ESCU
  python contentctl.py -p . generate -o dist/escu -pr ESCU
  ## update the -v 1 to 1.2
  python contentctl.py -p . init -t ESCU_Alerts -n ESCU_Alerts -v 1.2 -a "Your Name" -d "App built with security_content from github" -e my@email.com -c "My Company"
  ## copy your local savedsearches into the new version. **May not need to do this still testing**
  python savedsearchesreader.py
  cd dist
  tar -czvf ESCU_Alerts.tar.gz ESCU_Alerts/

  ```
