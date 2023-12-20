from ReportUtils import *
from optparse import OptionParser
import sys,re,time,shelve,json,commands,os
sys.path.append('pygeoip-master')
import pygeoip
geo = pygeoip.GeoIP('GeoIPCity.dat')

bold = "\033[1m"
reset = "\033[0;0m"

def stateCodeCityRegionMap():

        FH = open("stateCodeRegionMap","r")
        stateCodeRegionList = FH.readlines()
        FH.close()
        stateCodeRegionMap = {}
        regionCityMap = {}
        stateCodeStateMap ={}
        for stateCodeRegion in stateCodeRegionList:
                li = stateCodeRegion.split(',')
                stateCodeRegionMap[li[0]] = li[-1].rstrip('\n')
                stateCodeStateMap[li[0]] = li[1]
                if regionCityMap.has_key(li[-1].rstrip('\n')):
                        regionCityMap[li[-1].rstrip('\n')].append('%s' %(li[1]))
                else:
                        regionCityMap[li[-1].rstrip('\n')] = []
                        regionCityMap[li[-1].rstrip('\n')].append('%s' %(li[1]))

        return (stateCodeRegionMap,regionCityMap,stateCodeStateMap)

def unitConverter(value):
        if(value >= 1000 and value < 1000000):
                value = round(float(value)/float(1000),2)
                value = str(value)+' K'
        elif(value >= 1000000 and value < 1000000000):
                value = round(float(value)/float(1000000),2)
                value = str(value)+' M'
        elif(value >= 1000000000 and value < 1000000000000):
                value = round(float(value)/float(1000000000),2)
                value = str(value)+' G'
        elif(value >= 1000000000000 and value < 1000000000000000):
                value = round(float(value)/float(1000000000000),2)
                value = str(value)+' T'
        else:
                value = str(value)

        return value

def viewDurationIbParse():
        FH = open("ViewDurationIbFile","r")
        viewDurationIbList = FH.readlines()
        FH.close()
        viewDurationIb = {}
        for line in viewDurationIbList[1:]:
                li = line.split(',')
                if viewDurationIb.has_key(int(li[0])):
                        viewDurationIb[int(li[0])][li[1]] = li[2].rstrip('\n')
                else:
                        viewDurationIb[int(li[0])] = {}
                        viewDurationIb[int(li[0])][li[1]] = li[2].rstrip('\n')
        return viewDurationIb

def computeBitRate(bitrateProfileMap,serviceAccountId,url):

	if bitrateProfileMap.has_key(str(serviceAccountId)):
            	for regex in bitrateProfileMap[str(serviceAccountId)].keys():
                  	m = re.search(regex,url.rstrip('\n'))
                   	if m is not None:
                       		proFile =''.join( m.groups())
                             	if bitrateProfileMap[str(serviceAccountId)][regex].has_key(proFile):
                                   	bitRate = int(bitrateProfileMap[str(serviceAccountId)][regex][proFile])
					break
                             	else:
                                  	bitRate = 0
                   	else:
                             	bitRate = 0
     	else:
            	bitRate = 0

	return bitRate


def computeViewsSessions(geo,viewSessionsDict,stateCodeStateMap,viewDurationIb,bitrateProfileMap):
		
	channelRegionViewSessionsMap = {}
	uniqueViewersStateMap = {}
	uniqueViewersChannelMap = {}
	unicastDeliveryStateMap = {}
	unicastDeliveryChannelMap = {}
	viewDurationStateMap = {}
	viewDurationChannelMap = {}
	clientProfileUsageStateMap = {}
	clientProfileUsageMapHD = {}
	clientProfileUsageMapSD = {}

	for ipChannel in viewSessionsDict.keys():
		(ip,channel) = ipChannel.split('^')
		""" Computing Region Name from the ip address using maxmind database """
		d = geo.record_by_addr(ip)
		try:
                        stateCode = d['region_name']
                except:
                        stateCode = 'Unknown'
		
		try:
			stateName = stateCodeStateMap[stateCode]
		except:
			stateName = 'Unknown'
		""" Region Name Computed Successfully """

		if uniqueViewersStateMap.has_key(stateName):
			uniqueViewersStateMap[stateName][ip] = 1
		else:
			uniqueViewersStateMap[stateName] = {}
			uniqueViewersStateMap[stateName][ip] = 1

		if uniqueViewersChannelMap.has_key(channel):
                        uniqueViewersChannelMap[channel][ip] = 1
                else:
                        uniqueViewersChannelMap[channel] = {}
                        uniqueViewersChannelMap[channel][ip] = 1

		sortedList = sorted(viewSessionsDict[ipChannel])
		(iniEndTime,xDuration,prodBrandCat,scBytes,serviceAccountId,url) = sortedList[0].split('^')
		iniEndTime = float(iniEndTime)
		iniStartTime = iniEndTime-float(xDuration)
		key = '^'.join([channel,stateName,prodBrandCat,str(iniStartTime)])
		channelRegionViewSessionsMap[key] = 1

		for value in sortedList:
			(endTime,xDuration,prodBrandCat,bytes,serviceAccountId,url) = value.split('^')
			bytes = int(bytes)
			xDuration = float(xDuration)
			binTime = (int(endTime)/3600)*3600
                	if ((int(endTime)-binTime) < float(xDuration)):
                        	bytes = bytes*(float(int(endTime)-binTime)/float(xDuration))
                        	bytes = bytes+1

			bitRate = computeBitRate(bitrateProfileMap,serviceAccountId,url)

			""" Computing View Duration """
                	if viewDurationIb.has_key(serviceAccountId):
                        	if viewDurationIb[serviceAccountId].has_key('WP'):
                                	viewLogic = viewDurationIb[serviceAccountId]['WP']
                        	else:
                                	viewLogic = None
                                	xDuration = 10
                	else:
                        	viewLogic = None
                        	xDuration = 10

                	if viewLogic is not None:
                        	if viewLogic == 'x-Duration':
                                	if ((int(endTime)-binTime) <= float(xDuration)):
                                        	xDuration = int((int(endTime)-binTime))
                        	if viewLogic == 'ProfileBitRate':
					if bitRate == 0:
						xDuration = 0
                       	 	if bitRate != 0:
                                	xDuration = bytes/bitRate

                                if viewDurationStateMap.has_key(stateName):
                                        viewDurationStateMap[stateName] += xDuration
                                else:
                                        viewDurationStateMap[stateName] = xDuration

                                if viewDurationChannelMap.has_key(channel):
                                        viewDurationChannelMap[channel] += xDuration
                                else:
                                        viewDurationChannelMap[channel] = xDuration

				if clientProfileUsageStateMap.has_key(stateName):
                                        if clientProfileUsageStateMap[stateName].has_key(bitRate):
                                                clientProfileUsageStateMap[stateName][bitRate] += xDuration
                                        else:
                                                clientProfileUsageStateMap[stateName][bitRate] = xDuration
                                else:
                                        clientProfileUsageStateMap[stateName] = {}
                                        clientProfileUsageStateMap[stateName][bitRate] = xDuration
                        else:
                                if viewDurationStateMap.has_key(stateName):
                                        viewDurationStateMap[stateName] += xDuration
                                else:
                                        viewDurationStateMap[stateName] = xDuration

                                if viewDurationChannelMap.has_key(channel):
                                        viewDurationChannelMap[channel] += xDuration
                                else:
                                        viewDurationChannelMap[channel] = xDuration	

				if clientProfileUsageStateMap.has_key(stateName):
                                        if clientProfileUsageStateMap[stateName].has_key(bitRate):
                                                clientProfileUsageStateMap[stateName][bitRate] += xDuration
                                        else:
                                                clientProfileUsageStateMap[stateName][bitRate] = xDuration
                                else:
                                        clientProfileUsageStateMap[stateName] = {}
                                        clientProfileUsageStateMap[stateName][bitRate] = xDuration

				if " HD " in channel:
					if clientProfileUsageMapHD.has_key(stateName):
                                        	if clientProfileUsageMapHD[stateName].has_key(bitRate):
                                                	clientProfileUsageMapHD[stateName][bitRate] += xDuration
                                        	else:
                                                	clientProfileUsageMapHD[stateName][bitRate] = xDuration
                                	else:
                                        	clientProfileUsageMapHD[stateName] = {}
                                        	clientProfileUsageMapHD[stateName][bitRate] = xDuration
				else:
					if clientProfileUsageMapSD.has_key(stateName):
                                                if clientProfileUsageMapSD[stateName].has_key(bitRate):
                                                        clientProfileUsageMapSD[stateName][bitRate] += xDuration
                                                else:
                                                        clientProfileUsageMapSD[stateName][bitRate] = xDuration
                                        else:
                                                clientProfileUsageMapSD[stateName] = {}
                                                clientProfileUsageMapSD[stateName][bitRate] = xDuration

			""" View Duration Computed Successfully """

			if unicastDeliveryStateMap.has_key(stateName):
				unicastDeliveryStateMap[stateName] += bytes
			else:
				unicastDeliveryStateMap[stateName] = bytes

			if unicastDeliveryChannelMap.has_key(channel):
				unicastDeliveryChannelMap[channel] += bytes
			else:
				unicastDeliveryChannelMap[channel] = bytes

			startTime = float(endTime)-float(xDuration)
			if startTime >= iniEndTime:
                                diff = float(startTime)-float(iniEndTime)
                        else:
                                if startTime >= iniStartTime:
                                        diff = float(startTime)-float(iniStartTime)
                                else:
                                        diff = float(iniStartTime)-float(startTime)

			if(diff < 300):
                                iniEndTime = int(endTime)
                                iniStartTime = int(startTime)
                        else:
                                iniEndTime = int(endTime)
                                iniStartTime = int(startTime)
                                key = '^'.join([channel,stateName,prodBrandCat,str(startTime)])
                                channelRegionViewSessionsMap[key] = 1

	print "\nTotal View Sessions: %d\n" %(sum(channelRegionViewSessionsMap.values()))

	prodChannelRegionTotalSessionsMap = {}
	channelViewSessionsMap = {}
	stateViewSessionsMap = {}
	for key in channelRegionViewSessionsMap.keys():
		(channel,regionName,prodBrandCat,startTime) = key.split('^')
		if channelViewSessionsMap.has_key(channel):
			channelViewSessionsMap[channel] += 1
		else:
			channelViewSessionsMap[channel] = 1

		if stateViewSessionsMap.has_key(regionName):
                        stateViewSessionsMap[regionName] += 1
                else:
                        stateViewSessionsMap[regionName] = 1 

		(prod,brand,category) = prodBrandCat.split('-')
		if prodChannelRegionTotalSessionsMap.has_key(prod):
			if prodChannelRegionTotalSessionsMap[prod].has_key(channel):
				if prodChannelRegionTotalSessionsMap[prod][channel].has_key(regionName):
					prodChannelRegionTotalSessionsMap[prod][channel][regionName] += 1
				else:
					prodChannelRegionTotalSessionsMap[prod][channel][regionName] = 1
			else:
				prodChannelRegionTotalSessionsMap[prod][channel] = {}
				prodChannelRegionTotalSessionsMap[prod][channel][regionName] = 1
		else:
			prodChannelRegionTotalSessionsMap[prod] = {}
			prodChannelRegionTotalSessionsMap[prod][channel] = {}
			prodChannelRegionTotalSessionsMap[prod][channel][regionName] = 1
	
	print bold+"########## Client Profile Usage By State ###########\n"+reset
	for state in clientProfileUsageStateMap.keys():
		print bold+"STATE: "+reset+state
		print "%-40s%s" %(bold+"BITRATE"+reset,bold+"PERCENTAGE"+reset)
		for bitrate in sorted(clientProfileUsageStateMap[state].keys()):
			percentUsage = round((float(clientProfileUsageStateMap[state][bitrate])/float(sum(clientProfileUsageStateMap[state].values())))*100,2)
			print "%-30s%s" %(str(bitrate),str(percentUsage))
		print "\n"

	print bold+"########## Client Profile Usage (HD) By State ###########\n"+reset
        for state in clientProfileUsageMapHD.keys():
                print bold+"STATE: "+reset+state
                print "%-40s%s" %(bold+"BITRATE"+reset,bold+"PERCENTAGE"+reset)
                for bitrate in sorted(clientProfileUsageMapHD[state].keys()):
                        percentUsage = round((float(clientProfileUsageMapHD[state][bitrate])/float(sum(clientProfileUsageMapHD[state].values())))*100,2)
                        print "%-30s%s" %(str(bitrate),str(percentUsage))
                print "\n"

	print bold+"########## Client Profile Usage (SD) By State ###########\n"+reset
        for state in clientProfileUsageMapSD.keys():
                print bold+"STATE: "+reset+state
                print "%-40s%s" %(bold+"BITRATE"+reset,bold+"PERCENTAGE"+reset)
                for bitrate in sorted(clientProfileUsageMapSD[state].keys()):
                        percentUsage = round((float(clientProfileUsageMapSD[state][bitrate])/float(sum(clientProfileUsageMapSD[state].values())))*100,2)
                        print "%-30s%s" %(str(bitrate),str(percentUsage))
                print "\n"

	print bold+"########## Average View Duration Per Channel ###########\n"+reset
	print "%-50s%s" %(bold+"CHANNEL"+reset,bold+"AVG VIEW DURATION"+reset)
	for channel in viewDurationChannelMap.keys():
		avgDuration = viewDurationChannelMap[channel]/channelViewSessionsMap[channel]
		print "%-40s%s" %(channel,str(avgDuration))
	print "\n"

	print bold+"########## Average View Duration Per State ###########\n"+reset
        print "%-50s%s" %(bold+"STATE"+reset,bold+"AVG VIEW DURATION"+reset)
        for state in viewDurationStateMap.keys():
                avgDuration = viewDurationStateMap[state]/stateViewSessionsMap[state]
                print "%-40s%s" %(state,str(avgDuration))
        print "\n"

	print bold+"########## Total View Sessions Per Channel #############\n"+reset
	print "%-50s%s" %(bold+"CHANNEL"+reset,bold+"VIEW SESSIONS"+reset)
	for channel in channelViewSessionsMap.keys():
		print "%-40s%d" %(channel,channelViewSessionsMap[channel])
	print "\n"

	print bold+"########## Total View Sessions Per State #############\n"+reset
        print "%-40s%s" %(bold+"STATE"+reset,bold+"VIEW SESSIONS"+reset)
        for state in stateViewSessionsMap.keys():
                print "%-30s%d" %(state,stateViewSessionsMap[state])
        print "\n"

	print bold+"\n######### Unique Viewers By State ############\n"+reset
	print "%-40s%s" %(bold+"STATE"+reset,bold+"UNIQUE VIEWERS"+reset)
	for state in uniqueViewersStateMap.keys():
		uViewers = len(uniqueViewersStateMap[state].keys())
		print "%-30s%d" %(state,uViewers)
	print "\n"

	print bold+"\n######### Unique Viewers By Channel ############\n"+reset
        print "%-50s%s" %(bold+"CHANNEL"+reset,bold+"UNIQUE VIEWERS"+reset)
        for channel in uniqueViewersChannelMap.keys():
                uViewers = len(uniqueViewersChannelMap[channel].keys())
                print "%-40s%d" %(channel,uViewers)
        print "\n"

	print bold+"\n######### Unicast Delivery By State ############\n"+reset
	print "%-40s%s" %(bold+"STATE"+reset,bold+"UNICAST DELIVERY"+reset)
	for state in unicastDeliveryStateMap.keys():
		print "%-30s%s" %(state,unitConverter(unicastDeliveryStateMap[state]))
	print "\n"

	print bold+"\n######### Unicast Delivery By Channel ############\n"+reset
        print "%-50s%s" %(bold+"CHANNEL"+reset,bold+"UNICAST DELIVERY"+reset)
        for channel in unicastDeliveryChannelMap.keys():
                print "%-40s%s" %(channel,unitConverter(unicastDeliveryChannelMap[channel]))
	print "\n"

	print bold+"########## Per Channel Total View Sessions By State #############\n"+reset
	for prod in prodChannelRegionTotalSessionsMap.keys():
		for channel in prodChannelRegionTotalSessionsMap[prod].keys():
			print bold+"Prod"+reset+" --> "+prod+', '+bold+"Channel"+reset+" --> "+channel
			print "%-40s%s" %(bold+"REGION"+reset,bold+"VIEW SESSIONS"+reset)
			for region in prodChannelRegionTotalSessionsMap[prod][channel].keys():
				print "%-30s%d" %(region,prodChannelRegionTotalSessionsMap[prod][channel][region])
			print "\n"

def timeConvert(value):
        timeStamp = None
        if value > 3600:
                Hour = int(value)/3600
                value = int(value)%3600
                timeStamp = ''
                timeStamp = timeStamp+str(Hour)+'H'
        if value > 60:
                Min = int(value)/60
                value = int(value)%60
                if timeStamp is not None:
                        timeStamp = timeStamp+':'+str(Min)+'M'
                else:
                        timeStamp = ''
                        timeStamp = timeStamp+str(Min)+'M'
        if value < 60:
                Sec = value
                if timeStamp is not None:
                        timeStamp = timeStamp+':'+str(Sec)+'S'
                else:
                        timeStamp = ''
                        timeStamp = timeStamp+str(Sec)+'S'

        return timeStamp

def processLogData(headersIndexMap,logDict,assetIbMap,ignorePattern,serviceAccountId,devicesIbList,osIbList,HlsIbDict,geo,stateCodeStateMap,device,viewDurationIb,bitrateProfileMap):
	sessionDict = {}
	viewSessionDict = {}
	viewDurationChannelMap = {}
	viewDurationStateMap = {}
	conValidList = ['WP^Linear','WP^Event']
	device = device.lower()
	deviceList = device.split(',')
	
	for fileName in logDict.keys():
		if serviceAccountId == 'None':
			fileNameList = fileName.split('_')
			serviceAccountId = fileNameList[1]
                for logData in logDict[fileName]:
			fieldsList = logData.split('^')
			m = re.search(ignorePattern,fieldsList[headersIndexMap['cs-uri']])
                        if m is not None:
                                continue
			objContentType = None
			for regObjContentType in assetIbMap[serviceAccountId]:
				(regex,objType,contentType) = regObjContentType.split('^')
				regex = regex.strip('\n')
				m = re.search(regex,fieldsList[headersIndexMap['cs-uri']])
				if m is not None:
					objContentType = objType+'^'+contentType
					break

			if objContentType == None:
				continue
			if not (objContentType in conValidList):
				continue

			""" Computing Product,Brand and Category from the UserAgent """
                     	userAgent = fieldsList[headersIndexMap['cs(User-Agent)']]
                      	if userAgent != '""':
                             	userAgent = userAgent.replace('"','')
                                f = 0
                               	for ibVal in devicesIbList:
                                   	li = ibVal.split(',')
                                      	uaRegexp = li[0]
                                     	li[1] = li[1].replace(' ','')
                                     	li[2] = li[2].replace(' ','')
                                     	li[3] = li[3].replace(' ','')
                                    	m = re.search('%s' %(uaRegexp),userAgent)
                                    	if m is not None:
                                          	prodBrandCat = li[1]+'-'+li[2]+'-'+li[3].rstrip('\n')
                                             	f = 1
                                               	break
                           	if f == 0:
                                	prodBrandCat = 'Unknown-Unknown-Unknown'
                      	else:
                            	prodBrandCat = 'Unknown-Unknown-Unknown'
                     	"""UserAgent Computed Successfully"""

			(prod,brand,category) = prodBrandCat.split('-')
			if prod.lower() not in deviceList:
				if "all" in deviceList:
					pass
				else:
					continue

                    	""" Computing OS from the UserAgent """
                      	userAgent = fieldsList[headersIndexMap['cs(User-Agent)']]
                      	if userAgent != '""':
                             	userAgent = userAgent.replace('"','')
                             	g = 0
                            	for ibVal in osIbList:
                                     	li = ibVal.split(',')
                                    	uaRegexp = li[2]
                                     	m = re.search('%s' %(uaRegexp),userAgent)
                                     	if m is not None:
                                            	operatingSys = li[1]
                                              	g = 1
                                           	break
                           	if g == 0:
                                    	operatingSys = 'Unknown'
                   	else:
                            	operatingSys = 'Unknown'
                  	"""OS Computed Successfully"""

			""" Computing Channel Name from the HlsStreamIb file """
                       	for regex in HlsIbDict[serviceAccountId].keys():
                           	m = re.search(regex,fieldsList[headersIndexMap['cs-uri']])
                             	if m is not None:
                                   	url = ''.join(m.groups())
                                     	channelName = HlsIbDict[serviceAccountId][regex][url]
                                    	break
                            	else:
                                   	urlContent = fieldsList[headersIndexMap['cs-uri']].split('/')
                                    	channelName = urlContent[2]
                     	""" Channel Name Computed Successfully """

			key = '^'.join([serviceAccountId,fieldsList[headersIndexMap['c-ip']],prodBrandCat,operatingSys,objContentType])		
			dateTime = fieldsList[headersIndexMap['date']]+' '+fieldsList[headersIndexMap['time']]
			endTimeEpoch = int(time.mktime(time.strptime("%s" %(dateTime), "%Y-%m-%d %H:%M:%S")))
			value = '^'.join([str(endTimeEpoch),fieldsList[headersIndexMap['x-duration']],channelName])
			if sessionDict.has_key(key):
				sessionDict[key].append(value)
			else:
				sessionDict[key] = [value]

			viewSessionKey = '^'.join([fieldsList[headersIndexMap['c-ip']],channelName])
			viewSessionValue = '^'.join([str(endTimeEpoch),fieldsList[headersIndexMap['x-duration']],prodBrandCat,fieldsList[headersIndexMap['sc-bytes']],serviceAccountId,fieldsList[headersIndexMap['cs-uri']]])
			if viewSessionDict.has_key(viewSessionKey):
				viewSessionDict[viewSessionKey].append(viewSessionValue)
			else:
				viewSessionDict[viewSessionKey] = [viewSessionValue]

	computeViewsSessions(geo,viewSessionDict,stateCodeStateMap,viewDurationIb,bitrateProfileMap)
	fiosSessionDict = {}
	fiosChannelChangeFreqDict = {}
	for key in sessionDict.keys():
		sortedList = sorted(sessionDict[key])
		(iniEndTime,xDuration,channelName) = sortedList[0].split('^')
		iniStartTime = int(float(iniEndTime)-float(xDuration))
		iniEndTime = int(iniEndTime)
		iniKey = key+'^'+str(iniStartTime)
		fiosSessionDict[iniKey] = iniEndTime
		fiosChannelChangeFreqDict[key] = 1
		lastChannel = channelName
		for timeDurationChannel in sorted(sessionDict[key]):
			(endTime,xDuration,channelName) = timeDurationChannel.split('^')
			if lastChannel != channelName:
				fiosChannelChangeFreqDict[key] += 1
				lastChannel = channelName
			endTime = float(endTime)
			startTime = int(endTime-float(xDuration))
			if startTime >= iniEndTime:
                                diff = startTime-iniEndTime
                        else:
                                if startTime >= iniStartTime:
                                        diff = startTime-iniStartTime
                                else:
                                        diff = iniStartTime-startTime
			if(diff <= 300):
				fiosSessionDict[iniKey] = endTime
                                iniEndTime = endTime
                                iniStartTime = startTime
                        else:
				iniEndTime = endTime
                                iniStartTime = startTime
                                fiosKey = key+'^'+str(startTime)
                                fiosSessionDict[fiosKey] = endTime
	print "Total Fios Sessions: %d" %(len(fiosSessionDict.keys()))

	fiosStateChannelChangingMap = {}
	for key in fiosChannelChangeFreqDict.keys():
		li = key.split('^')
                ip = li[1]
                d = geo.record_by_addr(ip)
                try:
                        stateCode = d['region_name']
                except:
                        stateCode = 'Unknown'

                try:
                        stateName = stateCodeStateMap[stateCode]
                except:
                        stateName = 'Unknown'
	
		if fiosStateChannelChangingMap.has_key(stateName):
			fiosStateChannelChangingMap[stateName] += fiosChannelChangeFreqDict[key]
		else:
			fiosStateChannelChangingMap[stateName] = fiosChannelChangeFreqDict[key]

	fiosStateSessionsMap = {}
	for key in fiosSessionDict.keys():
                li = key.split('^')
                ip = li[1]
                d = geo.record_by_addr(ip)
                try:
                        stateCode = d['region_name']
                except:
                        stateCode = 'Unknown'

                try:
                        stateName = stateCodeStateMap[stateCode]
                except:
                        stateName = 'Unknown'

                if fiosStateSessionsMap.has_key(stateName):
                        fiosStateSessionsMap[stateName] += 1
                else:
                        fiosStateSessionsMap[stateName] = 1

	print bold+"############### Average Channel Changing Frequency By State #################"+reset
	print "%-50s%s" %(bold+"STATE"+reset,bold+"AVG CHANNEL CHANGING FREQUENCY"+reset)
	for state in fiosStateSessionsMap.keys():
		avgChannelChangingFreq = int(fiosStateChannelChangingMap[state])/int(fiosStateSessionsMap[state])
		print "%-40s%s" %(state,str(avgChannelChangingFreq))

	#computeViewsSessions(geo,viewSessionDict,stateCodeStateMap,viewDurationIb,bitrateProfileMap)
	#keyList = fiosChannelChangeFreqDict.keys()
	#keyEntryLength = len(keyList[0])+10
	#print "%-*s%s" %(keyEntryLength,'FIOS SESSION','CHANNEL CHANGING FREQ')
	#for key in fiosChannelChangeFreqDict.keys():
	#	print "%-*s%d" %(keyEntryLength,key,fiosChannelChangeFreqDict[key])

def getLogData(headers,path,startTime,endTime,pathType,serviceAccountId=None):
        (startDate,sHour) = startTime.split(":")
        (sYear,sMonth,sDay) = startDate.split("-")

        (endDate,eHour) = endTime.split(":")
        (eYear,eMonth,eDay) = endDate.split("-")

        logDict = {}
        if(startDate == endDate):
                sHour = int(sHour)
                eHour = int(eHour)
                for hour in range(sHour,eHour+1):
                        if hour < 10:
                                hour = '0'+str(hour)
                        else:
                                hour = str(hour)
                        logPathHttpAccess = path+'/'+sYear+'/'+sMonth+'/'+sDay+'/'+hour+'/'+'httpaccess'
                        logDict.update(read_files(headers,logPathHttpAccess,serviceAccountId))
			#logDict.update(test_read_files(headers,logPathHttpAccess,serviceAccountId))

        else:
                (startDate,sHour) = startTime.split(":")
                startTime = startDate+" "+sHour+":00:00"

                (endDate,eHour) = endTime.split(":")
                endTime = endDate+" "+eHour+":00:00"

                (status,startEpochTime) = commands.getstatusoutput("date -d \"%s\" \+%%s" %(startTime))
                (status,endEpochTime) = commands.getstatusoutput("date -d \"%s\" \+%%s" %(endTime))
                startEpochTime = int(startEpochTime)
                endEpochTime = int(endEpochTime)
                while(startEpochTime <= endEpochTime):
                        (sYear,sMonth,sDay,sHour,sMin,sSec,a,b,c) = time.gmtime(int(startEpochTime))
                        if sMonth < 10:
                                sMonth = '0'+str(sMonth)
                        if sDay < 10:
                                sDay = '0'+str(sDay)
                        if sHour < 10:
                                sHour = '0'+str(sHour)
                        logPathHttpAccess = path+'/'+str(sYear)+'/'+str(sMonth)+'/'+str(sDay)+'/'+str(sHour)+'/'+'httpaccess'
                        logDict.update(read_files(headers,logPathHttpAccess,serviceAccountId))
			#logDict.update(test_read_files(headers,logPathHttpAccess,serviceAccountId))
                        startEpochTime = startEpochTime+3600
        return logDict

def convertListToDict(List):
        ListDict = {}
        for i in range(len(List)):
                ListDict[List[i]] = i
        return ListDict

def getAssetInfoIbMap():
	FH = open('AssetInfoIb',"rb")
	assetIbList = FH.readlines()
	assetIbMap = {}
	for assetIbData in assetIbList:
		m = re.search('^\d',assetIbData)
		if m == None:
			continue
		li = assetIbData.split(';')
		accId = li[0]
		regex = li[5]
		objType = li[2]
		contentType = li[3]
		value = regex+'^'+objType+'^'+contentType
		if assetIbMap.has_key(accId):
			assetIbMap[accId].append(value)
		else:
			assetIbMap[accId] = [value]
	return assetIbMap

def profileBitrate():
        bitrateProfileMap = {}
        FH = open("ProfileBitrateIb","r")
        ibList = FH.readlines()
        FH.close()
        for line in ibList[1:]:
                (saId,regex,profile,bitrate) = line.split(';')
                bitrate = bitrate.rstrip('\n')
                if bitrateProfileMap.has_key(saId):
                        if bitrateProfileMap[saId].has_key(regex):
                                bitrateProfileMap[saId][regex][profile] = bitrate
                        else:
                                bitrateProfileMap[saId][regex] = {}
                                bitrateProfileMap[saId][regex][profile] = bitrate
                else:
                        bitrateProfileMap[saId] = {}
                        bitrateProfileMap[saId][regex] = {}
                        bitrateProfileMap[saId][regex][profile] = bitrate
        return bitrateProfileMap

parser = OptionParser(usage="usage: %prog [options] ",version="%prog 1.0")
parser.add_option("-s", "--starttime",
                        action="store",
                        dest="startTime",
                        type="str",
                        help="YYYY-MM-DD:HH example:2013-01-22:00")

parser.add_option("-e", "--endtime",
                        action="store",
                        dest="endTime",
                        type="str",
                        help="YYYY-MM-DD:HH example:2013-01-22:00")
parser.add_option("-p", "--path",
                        action="store",
                        dest="path",
                        type="str",
                        help="Path where logs are stored")
parser.add_option("-a", "--serviceaccountid",
                        action="store",
                        dest="serviceAccountId",
                        type="str",
                        default = None,
                        help="Service Account Id for which log files are required")
parser.add_option("-t", "--pathtype",
                        action="store",
                        dest="pathType",
                        type="str",
                        help="To tell if Path is HDFS or LOCAL")
parser.add_option("-d", "--deviceFilter",
                        action="store",
                        dest="device",
                        type="str",
			default = "All",
                        help="To tell if Path is HDFS or LOCAL")

options, args = parser.parse_args()

if(options.startTime != None and options.endTime != None and options.path != None and options.pathType != None):
        path = options.path
        startTime = options.startTime
        endTime = options.endTime
        serviceAccountId = options.serviceAccountId
        pathType = options.pathType
else:
        print "Insufficient Arguments entered...."
        (status,output) = commands.getstatusoutput("python %s --help" %(sys.argv[0]))
        print output
        sys.exit(0)

uaProdBrandCatMap = shelve.open('uaProdBrandCat')
headers = ['s-dns','date','time','x-duration','c-ip','c-port','c-vx-zone','cs-uri','cs(User-Agent)','sc-status','sc-stream-bytes','x-vx-serial','x-protohash','sc-bytes','s-cachestatus']
headersIndexMap = convertListToDict(headers)

FH = open('devicesIb',"r")
devicesIbList = FH.readlines()
FH.close()

FH = open('OsIb',"r")
osIbList = FH.readlines()
FH.close()

FH = open('IgnorePattern.json',"r")
ignorePatternDict = json.load(FH)
if ignorePatternDict['ServiceAccount'].has_key(serviceAccountId):
        ignorePattern = ignorePatternDict['ServiceAccount'][serviceAccountId]['IgnorePattern']
else:
        ignorePattern = ignorePatternDict['DefaultIgnorePattern']

HlsIb = open("HlsStreamIb","r")
HlsIbList = HlsIb.readlines()
HlsIb.close()

HlsIbDict = {}
for HlsIbLine in HlsIbList:
        IbContentList = HlsIbLine.split(';')
        (regex,url,channelName) = (IbContentList[1],IbContentList[2],IbContentList[4].rstrip('\n'))
        saId = IbContentList[0]
        if HlsIbDict.has_key(saId):
                if HlsIbDict[saId].has_key(regex):
                        HlsIbDict[saId][regex][url] = channelName
                else:
                        HlsIbDict[saId][regex] = {}
                        HlsIbDict[saId][regex][url] = channelName
        else:
                HlsIbDict[saId] = {}
                HlsIbDict[saId][regex] = {}
                HlsIbDict[saId][regex][url] = channelName

assetIbMap = getAssetInfoIbMap()
(stateCodeRegionMap,regionCityMap,stateCodeStateMap) = stateCodeCityRegionMap()
viewDurationIb = viewDurationIbParse()
bitrateProfileMap = profileBitrate()

logFileName = 'logFile_AdaptiveStreaming_'+options.startTime+'_'+options.endTime+'_'+str(options.serviceAccountId)+'.json'

if os.path.exists(logFileName):
        print "log file already present. Processing it..."
else:
        print "Creating Custom Log File for processing. Please wait..."
	logDict = getLogData(headers,path,startTime,endTime,pathType,serviceAccountId)
        with open(logFileName, 'wb') as fp:
                json.dump(logDict, fp)
        print "Custom Log File with the name %s created in the current directory for processing..." %(logFileName)

Log = open(logFileName,"r")
logDict = json.load(Log)

processLogData(headersIndexMap,logDict,assetIbMap,ignorePattern,serviceAccountId,devicesIbList,osIbList,HlsIbDict,geo,stateCodeStateMap,options.device,viewDurationIb,bitrateProfileMap)
