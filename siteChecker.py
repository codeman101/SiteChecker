#!/usr/bin/python3
from urllib.request import urlopen
import json
import requests
import string as  s


#--------------------------------------------------------------------------------------------------
# Name: searcherAndChecker
# 
# 
# Arguments:
# query: string to pass to DuckDuckGo API as a search query
#
# 
#
# About: Takes search query and passes it to DuckDuckgo API then get search resuts and passes them to
# VirusTotal's API. If one of the search results was detected by virustotal to have a virus then a message is 
# printed to the user containing the URL of the infected site.
# 
# code below the function body:
# Specific to this version of the program I created a type of generate brute force like for the search queries
# the generator starts with one character goes through the entire alphabet with that one character both upper and
# lower case then adds another character to the list. The process repeats for that character and then goes back
# to the pervious characters to rotate them through the alphabet with the new character at the end. For the list
# to be a search query it is converted into a string and passed to the searcherAndChecker function.
# The entire process stated above is repeated until the list grows to be 100 characters.
# 
#--------------------------------------------------------------------------------------------------

def searcherAndChecker(query):
    obj = urlopen('https://api.duckduckgo.com/?q=' + str(query) + '&format=json&pretty=1')  # search query
    bytes = obj.read()
    jtext = bytes.decode('utf8')
    jobj = json.loads(jtext)  # store json of query
    increasable = True  # variable to help determine if there're more links in the search to scan
    index = 0;  # index for json to go through and get the urls from the search
    urls = []  # list for store all the site urls
    while increasable:  # loop to get all the urls from the search
        try:
            urls.append(jobj["RelatedTopics"][index]["FirstURL"])
            index += 1
        except IndexError:
            increasable = False  # there're no more urls so stop the loop
        except KeyError:
            try:
                index2 = 0
                while True:
                    urls.append(jobj["RelatedTopics"][index]["Topics"][index2]["FirstURL"])
                    index2 += 1
            except:
                index += 1
        except:
            index += 1


    NumberOfSites = len(urls)  # get the nymber of urls
    counter = 0
    while counter < NumberOfSites:  # loop to go through all the urls and scan them
        scanParams = {'apikey': '',
                      'url': str(urls[counter])}
        scanResponse = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=scanParams)
        reportParams = {'apikey': '',
                        'resource': str(urls[counter])}
        reportResponse = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=reportParams)
        try:  # trying to translate response to json
            jReport = reportResponse.json()
            result = int(jReport['positives'])  # check if the scanned site was detected to have any viruses
            if result > 0:
                print("the site " + str(urls[counter]) + "was detected by one of the scanners to have a virsus")
                f = open('links.txt', 'a')
                f.write(str(urls[counter]))
                f.close()
            counter += 1
        except:  # request lib failed to translate response to json move to the next
            counter += 1

numOfChars = 100
currentChar = 0
searchStr = []
istring = s.ascii_letters
while currentChar < 100:
    searchStr.append('a')
    for letter in istring:
        searchStr[currentChar] = letter
        stl = ''.join(searchStr)
        searcherAndChecker(stl) #search through alphabet at current index of query string
    searchStr[currentChar] = 'a'
    currentChar = 0
    while currentChar < len(searchStr) and len(searchStr) > 1:
        for letter in istring:
            searchStr[currentChar] = letter
            stl = ''.join(searchStr)
            searcherAndChecker(stl) #go back to the beginning of query string and search through
            # every letter of alphabet
        searchStr[currentChar] = 'a'
        currentChar += 1
