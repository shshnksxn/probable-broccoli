import pexpect
import re
from optparse import OptionParser
import threading
import time
import sys
import logging

def performanceConfigStats():

        ##########################################################################################
        # This function fethes the performance configuration data from the performance.conf file #
        ##########################################################################################
        try:
                f = open('performance.conf', 'r')
                perfFile = f.readlines()
                perfConfDict = {}
                for line in perfFile:
                        if 'Monitor_Server' in line:
                                m = re.search('.+?=\s+(.*)',line)
                                mIp = m.group(1)
                                perfConfDict[mIp] = []
                        if 'Username' in line:
                                m = re.search('.+?=\s+(.*)',line)
                                perfConfDict[mIp].append(m.group(1).rstrip('\r\n'))
                        if 'Password' in line:
                                m = re.search('.+?=\s+(.*)',line)
                                perfConfDict[mIp].append(m.group(1).rstrip('\r\n'))
                        if 'Monitor_Process' in line:
                                m = re.search('.+?=\s+(.*)',line)
                                perfConfDict[mIp].append(m.group(1).rstrip('\r\n'))
                        if 'Monitor_Interval' in line:
                                m = re.search('.+?=\s+(.*)',line)
                                perfConfDict[mIp].append(m.group(1).rstrip('\r\n'))
                return perfConfDict
        except IOError:
                print "Can't read file. Please check if the performance.conf file is present in the src directory"
                sys.exit()

def connectRemoteMachines(machineDict):

	rMachineSSHChildDict = {}
	for rMachine in machineDict.keys():
		child = pexpect.spawn ('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s@%s' %(machineDict[rMachine][0].rstrip('\n'),rMachine))
        	i = child.expect (['assword: ', '[#\$] ','> ','no\)\? '])
        	if i==0:
			if(len(machineDict[rMachine])>1):
                		child.sendline (machineDict[rMachine][1])
                		j = child.expect (['> ','assword: ','[#\$] '])
                		if j==0:
                        		child.sendline('en')
                        		child.expect ('[#\$] ')
                        		child.sendline('_shell')
                        		child.expect ('[#\$] ')
                        		rMachineSSHChildDict[rMachine] = child
                		elif j==1:
                        		print"Wrong password entered for %s. Please specify the correct password in command line options" %(rMachine)
                        		child.kill(0)
                		elif j==2:
                        		rMachineSSHChildDict[rMachine] = child

        	elif i==1:
                	rMachineSSHChildDict[rMachine] = child

        	elif i==2:
                	child.sendline('en')
                	child.expect ('[#\$] ')
                	child.sendline('_shell')
                	child.expect ('[#\$] ')
                	rMachineSSHChildDict[rMachine] = child

		elif i==3:
			child.sendline('yes')
			print child.before
			j = child.expect (['> ','assword: ','[#\$] '])
                        if j==0:
                                child.sendline('en')
                                child.expect ('[#\$] ')
                                child.sendline('_shell')
                                child.expect ('[#\$] ')
                                rMachineSSHChildDict[rMachine] = child
                        elif j==1:
				if(len(machineDict[rMachine])>1):
                                	child.sendline (machineDict[rMachine][1].rstrip('\n'))
                                	k = child.expect (['> ','assword: ','[#\$] '])
                                	if k==0:
                                        	child.sendline('en')
                                        	child.expect ('[#\$] ')
                                        	child.sendline('_shell')
                                        	child.expect ('[#\$] ')
                                        	rMachineSSHChildDict[rMachine] = child
                                	elif k==1:
                                        	print"Wrong password entered for %s. Please specify the correct password in command line options" %(rMachine)
                                        	child.kill(0)
                                	elif k==2:
                                        	rMachineSSHChildDict[rMachine] = child


                        elif j==2:
                        	rMachineSSHChildDict[rMachine] = child

	return(rMachineSSHChildDict)

def unpackTarFile(rSSHChild,tarFile,machineDict,machineIP,pythonFile='NONE'):

	if 'NONE' in pythonFile:
		m = re.search('(.*?)\.tar',tarFile)
        	if m is not None:
                	dirName = m.group(1)
		rSSHChild.sendline('sudo tar -xvzf %s' %(tarFile))
		j = rSSHChild.expect(['[#\$] ','password '])
                if j == 1:
                        if(len(machineDict[rSSHChild]) > 1):
                                rSSHChild.sendline(machineDict[machineIP][1])
                                rSSHChild.expect('[#\$] ')
  		rSSHChild.sendline('cd %s' %(dirName))
		rSSHChild.expect('[#\$] ')
  		rSSHChild.sendline('sudo python setup.py build')
		j = rSSHChild.expect(['[#\$] ','password '])
                if j == 1:
                        if(len(machineDict[rSSHChild]) > 1):
                                rSSHChild.sendline(machineDict[machineIP][1])
                                rSSHChild.expect('[#\$] ')
    		rSSHChild.sendline('sudo python setup.py install')
		j = rSSHChild.expect(['[#\$] ','password '])
                if j == 1:
                        if(len(machineDict[rSSHChild]) > 1):
                                rSSHChild.sendline(machineDict[machineIP][1])
                                rSSHChild.expect('[#\$] ')
   		rSSHChild.sendline('cd ..')
    		rSSHChild.expect('[#\$] ')
	else:
		rSSHChild.sendline('sudo python %s %s' %(pythonFile,tarFile))
		j = rSSHChild.expect(['[#\$] ','password '])
                if j == 1:
                        if(len(machineDict[rSSHChild]) > 1):
                                rSSHChild.sendline(machineDict[machineIP][1])
                                rSSHChild.expect('[#\$] ')

	return(rSSHChild)

def remoteMachineEnvSetup(rSSHChild,machineIP,machineDict):

	cond = threading.Condition()
	global threadSyncList
	print "Creating sandbox on the remote machine %s...." %(machineIP)	
	logging.info('Creating sandbox on the remote machine %s....',machineIP)
	rSSHChild.sendline('mkdir -p /tmp/LoadTesting')
	rSSHChild.expect('[#\$] ')
	logging.info('Created dirctory /tmp/LoadTesting on machine %s',machineIP)
	rSSHChild.sendline('cd /tmp/LoadTesting')
        rSSHChild.expect('[#\$] ')
	rSSHChild.sendline('scp root@192.168.0.63:/home/sunil/LoadTesting.tar .')
	i = rSSHChild.expect(['assword: ','no\)\? '])
	if i==0:
		rSSHChild.sendline('guavus')
		rSSHChild.expect('[#\$] ',timeout=300)
		print "Copying of tar file completed on %s" %(machineIP)
		logging.info('Copying of tar file completed on %s',machineIP)
	elif i==1:
		rSSHChild.sendline('yes')
                rSSHChild.expect('assword: ')
		rSSHChild.sendline('guavus')
                rSSHChild.expect('[#\$] ',timeout=300)
		print "Copying of tar file completed on %s" %(machineIP)
		logging.info('Copying of tar file completed on %s',machineIP)

	print "Extracting the tar file on machine %s" %(machineIP)
	logging.info('Extracting the tar file on machine %s',machineIP)
	rSSHChild.sendline('sudo tar -xvf LoadTesting.tar')
	j = rSSHChild.expect(['[#\$] ','password '])
	if j == 1:
		if(len(machineDict[machineIP]) > 1):
			rSSHChild.sendline(machineDict[machineIP][1])
			rSSHChild.expect('[#\$] ')
	print "Tar File Extracted successfully"
	print "Unpacking and Installing the Selenium Framework Tar file on machine %s" %(machineIP)
	rSSHChild = unpackTarFile(rSSHChild,'robotframework-seleniumlibrary-2.6.tar.gz',machineDict,machineIP)
	print "Selenium Framework Installation Completed Successfully on machine %s" %(machineIP)
	print "Unpacking and Installing pexpect module on machine %s" %(machineIP)
	rSSHChild = unpackTarFile(rSSHChild,'pexpect-2.3.tar.gz',machineDict,machineIP)
	print "expect Module Installation Completed Successfully on machine %s" %(machineIP)
	print "Unpacking and installing robot framework on machine %s" %(machineIP)
	rSSHChild = unpackTarFile(rSSHChild,'robotframework-2.5.6.tar.gz',machineDict,machineIP)
	print "robot framework succsccfully installed on machine %s" %(machineIP)

	rSSHChild.sendline('ls /usr/local/lib/ | grep -i --color=never \"python\" | awk \'$1 ~ /^python2/ {print $1}\'')
        rSSHChild.expect('[#\$] ')
        pythonPackageList = rSSHChild.before.split('\n')
        pythonPackageList = pythonPackageList[1:len(pythonPackageList)-1]
        if(len(pythonPackageList) > 1):
                pythonVersionList = []
                for values in pythonPackageList:
                        m = re.search('python(.*)',values)
                        if m is not None:
                                pythonVersionList.append(float(m.group(1)))
                pythonVersion = max(pythonVersionList)
                pythonVersion = str(pythonVersion).rstrip('\r')
                pythonVersion = str(pythonVersion).rstrip('\n')
                pythonVersion = 'python'+str(pythonVersion)
        else:
                pythonVersion = pythonPackageList[0].rstrip('\n')
                pythonVersion = pythonPackageList[0].rstrip('\r')

	print "Installing setuptools on machine %s" %(machineIP)
	if(pythonVersion == 'python2.7'):
		rSSHChild.sendline('cd FunkLoadAndDependency/setuptool2.7')
		rSSHChild.expect('[#\$] ')
		rSSHChild.sendline('sudo sh setuptools-0.6c11-py2.7.egg')
		j = rSSHChild.expect(['[#\$] ','password '])
        	if j == 1:
                	if(len(machineDict[machineIP]) > 1):
                        	rSSHChild.sendline(machineDict[machineIP][1])
                        	rSSHChild.expect('[#\$] ',timeout=300)
				rSSHChild.sendline('cd ../../')
				rSSHChild.expect('[#\$] ')
		else:
			rSSHChild.sendline('cd ../')
          		rSSHChild.expect('[#\$] ')
	else:
		rSSHChild.sendline('cd FunkLoadAndDependency/setuptool2.6')
                rSSHChild.expect('[#\$] ')
                rSSHChild.sendline('sudo sh setuptools-0.6c11-py2.6.egg')
                j = rSSHChild.expect(['[#\$] ','password '])
                if j == 1:
                        if(len(machineDict[machineIP]) > 1):
                                rSSHChild.sendline(machineDict[machineIP][1])
                                rSSHChild.expect('[#\$] ',timeout=300)
		else:
			rSSHChild.sendline('cd ../')
                        rSSHChild.expect('[#\$] ')
	print "setuptools installations completed on machine %s" %(machineIP)

	print "Unpacking and Installing the Funkload Dependencies on machine %s" %(machineIP)
        rSSHChild = unpackTarFile(rSSHChild,'docutils-0.7.tar.gz',machineDict,machineIP,'ez_setup.py')
        rSSHChild = unpackTarFile(rSSHChild,'webunit-1.3.9.tar.gz',machineDict,machineIP,'ez_setup.py')
        rSSHChild = unpackTarFile(rSSHChild,'tcpwatch-1.3.tar.gz',machineDict,machineIP,'ez_setup.py')
        print "Installation of Funkload Dependencies completed successfully on machine %s...." %(machineIP)


	print "Installing FunkLoad Environment on machine %s" %(machineIP)
	rSSHChild.sendline('cd ../FunkLoad')
	rSSHChild.expect('[#\$] ')
	rSSHChild.sendline('cd funkload-1.16.0')
        rSSHChild.expect('[#\$] ')
	rSSHChild.sendline('sudo python setup.py build')
	j = rSSHChild.expect(['[#\$] ','password '])
        if j == 1:
        	if(len(machineDict[machineIP]) > 1):
                  	rSSHChild.sendline(machineDict[machineIP][1])
                    	rSSHChild.expect('[#\$] ')
        rSSHChild.sendline('sudo python setup.py install')
	j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
              	if(len(machineDict[machineIP]) > 1):
              		rSSHChild.sendline(machineDict[machineIP][1])
                    	rSSHChild.expect('[#\$] ',timeout=300)
	print "Installation of FunkLoad Completed Successfully on machine %s.... " %(machineIP)

	rSSHChild.sendline('scp root@192.168.0.63:/home/sunil/performance.conf /tmp/LoadTesting/FunkLoad/funkload-1.16.0/src/')
        i = rSSHChild.expect(['assword: ','no\)\? '])
        if i==0:
                rSSHChild.sendline('guavus')
                rSSHChild.expect('[#\$] ',timeout=300)
                print "Copying of performance.conf file completed on %s" %(machineIP)
                logging.info('Copying of performance.conf file completed on %s',machineIP)
        elif i==1:
                rSSHChild.sendline('yes')
                rSSHChild.expect('assword: ')
                rSSHChild.sendline('guavus')
                rSSHChild.expect('[#\$] ',timeout=300)
                print "Copying of performance.conf file completed on %s" %(machineIP)
                logging.info('Copying of performance.conf file completed on %s',machineIP)

	print "Environment Created Successfully on machine %s" %(machineIP)
	cond.acquire()
	threadSyncList.append('1')
     	cond.release()

def runSeleniumServer(rSSHChild,UIipAddr,machineDict,machineIP,profileDir):

	print "\nRunning Selenium server on machine %s" %(machineIP)
	seleniumProcCond = threading.Condition()
	global seleniumServerThreadSyncList

	"""
	rSSHChild.sendline('cd ~/.mozilla/firefox')
	rSSHChild.expect('[#\$] ')

	rSSHChild.sendline('cat profiles.ini | grep -c "\[Profile"')
	rSSHChild.expect('[#\$] ')
	profileList = (rSSHChild.before).split('\n')
	profileCount = profileList[1].rstrip('\r')
	
	rSSHChild.sendline('sudo cat /tmp/LoadTesting/profile.txt | sed \'s/\[Profile0\]/\[Profile%s\]/g\' -i /tmp/LoadTesting/profile.txt' %(profileCount))
	j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)

	rSSHChild.sendline('grep -i w61255xf.loadProfile profiles.ini')
	rSSHChild.expect('[#\$] ')
	rSSHChild.sendline('echo $?')
        rSSHChild.expect('[#\$] ')
	commandStatusList = (rSSHChild.before).split('\n')
	commandStatus = commandStatusList[1].rstrip('\r')
	if(commandStatus == '0'):
		rSSHChild.sendline('sudo cat /tmp/LoadTesting/profile.txt >> profiles.ini')
		j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        	if j == 1:
                	if(len(machineDict[machineIP]) > 1):
                        	rSSHChild.sendline(machineDict[machineIP][1])
                        	rSSHChild.expect('[#\$] ',timeout=300)

	rSSHChild.sendline('ls | grep -i --color=never \"default\"')
	rSSHChild.expect('[#\$] ')
	defaultProfileList = rSSHChild.before.split('\n')
	defaultProfile = defaultProfileList[1].rstrip('\r')
	print "Default profile is: %s" %(defaultProfile)

	rSSHChild.sendline('sudo cp -R /tmp/LoadTesting/w61255xf.loadProfile/ .')
	j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)

	rSSHChild.sendline('sudo chmod 777 w61255xf.loadProfile')
        j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)

	rSSHChild.sendline('cd w61255xf.loadProfile')
	rSSHChild.expect('[#\$] ')

	rSSHChild.sendline('sudo chown guavus *')
        j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)
	
	rSSHChild.sendline('sudo rm -f cert_override.txt')
	j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)
	rSSHChild.sendline('sudo cp /tmp/LoadTesting/cert_override.txt .')
	j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
	if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)
	rSSHChild.sendline('sudo sed \'s/192.168.100.242/%s/g\' -i cert_override.txt' %(UIipAddr))
	j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)
	"""		
	rSSHChild.sendline('export DISPLAY=:0.0')
        rSSHChild.expect('[#\$] ')

	rSSHChild.sendline('ls /usr/local/lib/ | grep -i --color=never \"python\" | awk \'$1 ~ /^python2/ {print $1}\'')
	rSSHChild.expect('[#\$] ')
	pythonPackageList = rSSHChild.before.split('\n')
	pythonPackageList = pythonPackageList[1:len(pythonPackageList)-1]
	if(len(pythonPackageList) > 1):
		pythonVersionList = []
		for values in pythonPackageList:
			m = re.search('python(.*)',values)
			if m is not None:
				pythonVersionList.append(float(m.group(1)))
		pythonVersion = max(pythonVersionList)
		pythonVersion = str(pythonVersion).rstrip('\r')
		pythonVersion = str(pythonVersion).rstrip('\n')
		pythonVersion = 'python'+str(pythonVersion)
	else:
		pythonVersion = pythonPackageList[0].rstrip('\n')
		pythonVersion = pythonPackageList[0].rstrip('\r')

	rSSHChild.sendline('cd /usr/local/lib/%s' %(pythonVersion))
	rSSHChild.expect('[#\$] ')
	rSSHChild.sendline('ls site-packages/SeleniumLibrary/')
	rSSHChild.expect('[#\$] ')
	rSSHChild.sendline('echo $?')
	rSSHChild.expect('[#\$] ')
	commandStatusList = rSSHChild.before.split('\n')
	commandStatus = commandStatusList[1].rstrip('\r')
	if commandStatus == '0':	
		packageDir = 'site-packages'
	else:
		packageDir = 'dist-packages'
	rSSHChild.sendline('sudo rm -f /usr/local/lib/%s/%s/SeleniumLibrary/lib/user-extensions.js' %(pythonVersion,packageDir))
        j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)
	rSSHChild.sendline('sudo cp /tmp/LoadTesting/user-extensions.js /usr/local/lib/%s/%s/SeleniumLibrary/lib/' %(pythonVersion,packageDir))
        j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)
	seleniumCommand = 'java -jar /usr/local/lib/%s/%s/SeleniumLibrary/lib/selenium-server.jar -userExtensions /usr/local/lib/%s/%s/SeleniumLibrary/lib/user-extensions.js -singleWindow -firefoxProfileTemplate ~/.mozilla/firefox/%s' %(pythonVersion,packageDir,pythonVersion,packageDir,profileDir)

	print "Selenium command is: %s" %(seleniumCommand)
	###################### Checking if any Selenium Server is already running #################################

	print "Checking if a selenium process is already running...."
	rSSHChild.sendline('ps -aef | grep -i --color=never firefoxProfileTemplate | grep -v --color=never grep | awk \'{print $2}\'')
	rSSHChild.expect('[#\$] ')
	seleniumProcessList = rSSHChild.before.split('\n')
	if(len(seleniumProcessList) > 1):
		seleniumProcess = seleniumProcessList[1].rstrip('\r')
		rSSHChild.sendline('sudo kill -9 %s' %(seleniumProcess))
		j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        	if j == 1:
                	if(len(machineDict[machineIP]) > 1):
                        	rSSHChild.sendline(machineDict[machineIP][1])
                        	rSSHChild.expect('[#\$] ',timeout=300)
	else:
		print "No selenium process is already running"
	
	###################### Running Selenium Server in background ###########################
	rSSHChild.sendline('%s 2>/dev/null &' %(seleniumCommand))
	j = rSSHChild.expect(['[#\$] ','password '],timeout=300)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=300)

	print "Selenium Server run successfully on machine %s with selenium command: %s" %(machineIP,seleniumCommand)
	seleniumProcCond.acquire()
	seleniumServerThreadSyncList.append('1')
	seleniumProcCond.release()
		

def pythonCommandGenerator(rSSHChild,functionsList,filename,filepath,cycles,machineDict,machineIP):

	if(len(functionsList)>1):
		for func in functionsList:
			func = func+" "
		func = func.rstrip(" ")
	else:
		func = functionsList[0]

	rSSHChild.sendline('cd %s' %(filepath))
	rSSHChild.expect('[#\$] ')
	rSSHChild.sendline('pwd')
        rSSHChild.expect('[#\$] ')
	currentDir = ((rSSHChild.before).split('\n'))[1].rstrip('\r')
	print "Current Working Directory is %s" %(currentDir)
	command = 'sudo python /tmp/LoadTesting/FunkLoad/funkload-1.16.0/src/funkload/BenchRunner.py -c %s -D 4 %s %s' %(cycles,filename,func)
	print "Executing Load Command on machine %s" %(machineIP)
	print "Load Command: %s" %(command)
	rSSHChild.sendline(command)
	j = rSSHChild.expect(['[#\$] ','password '],timeout=3000)
        if j == 1:
                if(len(machineDict[machineIP]) > 1):
                        rSSHChild.sendline(machineDict[machineIP][1])
                        rSSHChild.expect('[#\$] ',timeout=3000)

def monitoRemoteMachineLoadRunStatus(rSSHChild,processName = 'python /tmp/LoadTesting/FunkLoad/funkload-1.16.0/src/funkload/BenchRunner.py'):
	
	condProcess = threading.Condition()
	global remoteProcessMonotorThreadSyncList
	rSSHChild.sendline('ps -aef | grep -i --color=never \"%s\" | grep -v --color=never grep | grep -vi --color=never screen | awk \'{print $2}\'' %(processName))
        rSSHChild.expect('[#\$] ')	
	psidList = rSSHChild.before.split('\n')
	processId = str(psidList[1]).rstrip('\r')
	
	remoteProcessMonitorVar = 1
	while(remoteProcessMonitorVar):
		rSSHChild.sendline('kill -0 %s' %(processId))
		rSSHChild.expect('[#\$] ')
		rSSHChild.sendline('echo $?')
		rSSHChild.expect('[#\$] ')
		processStatusList = rSSHChild.before.split('\n')
		processStatus = processStatusList[1].rstrip('\r')
		if processStatus == '0':
			time.sleep(1)
			continue
		else:
			remoteProcessMonitorVar = 0

	condProcess.acquire()
	remoteProcessMonotorThreadSyncList.append('1')
	condProcess.release()

def getFile(rSSHChild,filePath,fileName,machineIP):

	global remoteCopyThreadSyncList
	cond = threading.Condition()
	localfileName = machineIP+'_'+fileName
        rSSHChild.sendline('cd %s' %(filePath))
        rSSHChild.expect('[#\$] ')
        rSSHChild.sendline('scp %s root@192.168.0.63:/home/sunil/%s' %(fileName,localfileName))
        i = rSSHChild.expect(['assword: ','no\)\? '])

        if i==0:
                rSSHChild.sendline('guavus')
                rSSHChild.expect('[#\$] ',timeout=600)
		cond.acquire()
		remoteCopyThreadSyncList.append('1')
		cond.release()
        elif i==1:
                rSSHChild.sendline('yes')
                rSSHChild.expect('assword: ')
                rSSHChild.sendline('guavus')
                rSSHChild.expect('[#\$] ',timeout=600)
		cond.acquire()
		remoteCopyThreadSyncList.append('1')
		cond.release()

def runCopyThreading(rSSHChildDict,filepath,filename):

	global remoteCopyThreadSyncList
     	remoteCopyThreadList = []
    	remoteCopyThreadSyncList = []

    	for rSSHChild in rSSHChildDict.keys():
        	remoteCopyThreadList.append(threading.Thread(target=getFile, args=(rSSHChildDict[rSSHChild],filepath,filename,rSSHChild,)))

   	if(len(remoteCopyThreadList) > 0):
        	for thread in remoteCopyThreadList:
                 	thread.start()

  	threadControlVariable = 1
     	while(threadControlVariable):
        	if(len(remoteCopyThreadSyncList) == len(remoteCopyThreadList)):
                 	for thread in remoteCopyThreadList:
                         	thread.join()
         		threadControlVariable = 0

def checkFilePresence(perfMachineSSHChild,filename):

	perfMachineSSHChild.sendline('ls %s' %(filename))
	perfMachineSSHChild.expect('[#\$] ')
	perfMachineSSHChild.sendline('echo $?')
	perfMachineSSHChild.expect('[#\$] ')
	fileCheckStatusList = perfMachineSSHChild.before.split('\n')
	fileCheckStatus = fileCheckStatusList[1]
	fileCheckStatus = fileCheckStatus.rstrip('\r')
	if fileCheckStatus == '0':
		return 1
	else:
		return 0

def getAtlasLogFiles(perfMachineSSHChild,filepath,filename,cycle,perfMachineIP):

	global perfMachineCopyLogFilesThreadSyncList
	cond = threading.Condition()
	updatedFileName = str(perfMachineIP)+'_'+str(cycle)+'_'+filename
	perfMachineSSHChild.sendline('ls %s' %(filepath))
	perfMachineSSHChild.expect('[#\$] ')
	perfMachineSSHChild.sendline('echo $?')
        perfMachineSSHChild.expect('[#\$] ')
	pathCheckList = perfMachineSSHChild.before.split('\n')
	pathCheckStatus = pathCheckList[1].rstrip('\r')
	if(pathCheckStatus == '0'):
		perfMachineSSHChild.sendline('cd %s' %(filepath))
		perfMachineSSHChild.expect('[#\$] ')
		if(checkFilePresence(perfMachineSSHChild,filename)):
			perfMachineSSHChild.sendline('scp %s root@192.168.0.63:/home/sunil/%s' %(filename,updatedFileName))
			i = perfMachineSSHChild.expect(['assword: ','no\)\? '])

        		if i==0:
                		perfMachineSSHChild.sendline('guavus')
                		perfMachineSSHChild.expect('[#\$] ',timeout=3000)
				perfMachineSSHChild.sendline('\\>%s%s' %(filepath,filename))
                        	perfMachineSSHChild.expect('[#\$] ')
                		cond.acquire()
                		perfMachineCopyLogFilesThreadSyncList.append('1')
                		cond.release()
        		elif i==1:
                		perfMachineSSHChild.sendline('yes')
                		perfMachineSSHChild.expect('assword: ')
                		perfMachineSSHChild.sendline('guavus')
                		perfMachineSSHChild.expect('[#\$] ',timeout=3000)
				perfMachineSSHChild.sendline('\\>%s%s' %(filepath,filename))
                        	perfMachineSSHChild.expect('[#\$] ')
                		cond.acquire()
                		perfMachineCopyLogFilesThreadSyncList.append('1')
                		cond.release()
		else:
			cond.acquire()
			perfMachineCopyLogFilesThreadSyncList.append('1')
			cond.release()
	else:
		cond.acquire()
             	perfMachineCopyLogFilesThreadSyncList.append('1')
            	cond.release()

def checkAtlasFlexLogFilePerCycle(rSSHChild,filename):
	
	condLog = threading.Condition()
	global copyAtlasFlexLogFilesThreadSyncList
	commandStatus = 1
	while commandStatus:
		rSSHChild.sendline('ls %s' %(filename))
		rSSHChild.expect('[#\$] ')
		rSSHChild.sendline('echo $?')
        	rSSHChild.expect('[#\$] ')
        	commandStatusList = rSSHChild.before.split('\n')
        	commandStatus = commandStatusList[1].rstrip('\r')
		if commandStatus == '0':
			rSSHChild.sendline('rm %s' %(filename))
                        rSSHChild.expect('[#\$] ')
                        commandStatus=0
			condLog.acquire()
			copyAtlasFlexLogFilesThreadSyncList.append('1')
			condLog.release()


def copyAtlasFlexLogFiles(cycles,machineDict,filepath,perfMachineSSHDict):

	global copyAtlasFlexLogFilesThreadSyncList
	rMachineSSHChildDict = connectRemoteMachines(machineDict)
	cycleList = cycles.split(':')
	for cycle in cycleList:
		copyAtlasFlexLogFilesThreadSyncList = []
		copyAtlasFlexLogThreadList = []
		fileName = 'cycle_'+str(cycle)
		for rSSHChild in rMachineSSHChildDict.keys():
			rMachineSSHChildDict[rSSHChild].sendline('cd %s' %(filepath))
			rMachineSSHChildDict[rSSHChild].expect('[#\$] ')	
			copyAtlasFlexLogThreadList.append(threading.Thread(target=checkAtlasFlexLogFilePerCycle, args=(rMachineSSHChildDict[rSSHChild],fileName,)))
		if(len(copyAtlasFlexLogThreadList) > 0):
			for thread in copyAtlasFlexLogThreadList:
				thread.start()
		threadControlVariable = 1
		while(threadControlVariable):
			if(len(copyAtlasFlexLogFilesThreadSyncList) == len(copyAtlasFlexLogThreadList)):
				for thread in copyAtlasFlexLogThreadList:
					thread.join()
			threadControlVariable = 0
		del(rMachineSSHChildDict)
		global perfMachineCopyLogFilesThreadSyncList
		perfMachineCopyLogFilesThreadSyncList = []
		perfMachineCopyLogFileThreadList = []
		for perfMachine in perfMachineSSHDict.keys():
			perfMachineCopyLogFileThreadList.append(threading.Thread(target=getAtlasLogFiles, args=(perfMachineSSHDict[perfMachine],'/data/apache-tomcat/apache-tomcat-7.0.22/bin/','atlas.log',cycle,perfMachine,)))
		
		if(len(perfMachineCopyLogFileThreadList) > 0):
			for thread in perfMachineCopyLogFileThreadList:
				thread.start()
		threadControlVariable = 1
		while threadControlVariable:
			if(len(perfMachineCopyLogFilesThreadSyncList) == len(perfMachineCopyLogFileThreadList)):
				for thread in perfMachineCopyLogFileThreadList:
					thread.join()
			threadControlVariable = 0

		perfMachineCopyLogFilesThreadSyncList = []
                perfMachineCopyLogFileThreadList = []
                for perfMachine in perfMachineSSHDict.keys():
                        perfMachineCopyLogFileThreadList.append(threading.Thread(target=getAtlasLogFiles, args=(perfMachineSSHDict[perfMachine],'/data/apache-tomcat/apache-tomcat-7.0.22/bin/','flex.log',cycle,perfMachine,)))

                if(len(perfMachineCopyLogFileThreadList) > 0):
                        for thread in perfMachineCopyLogFileThreadList:
                                thread.start()
                threadControlVariable = 1
                while threadControlVariable:
                        if(len(perfMachineCopyLogFilesThreadSyncList) == len(perfMachineCopyLogFileThreadList)):
                                for thread in perfMachineCopyLogFileThreadList:
                                        thread.join()
                        threadControlVariable = 0
		
		
def mergeStatFiles(rSSHChildDict,dict,fname,numFields):

	regExp = ''
	for i in xrange(numFields-1):
		regExp = regExp+'(.*?)\s+'
	regExp = regExp+'\[(.*?)\]'
	for machineIP in rSSHChildDict.keys():
		filename = machineIP+'_'+fname
		readFile = open('%s' %(filename), "r")
		lines = readFile.readlines()
		for line in lines:
			m = re.search('%s' %(regExp),line.rstrip('\n'))
			if m is not None:
				valList = []
				for i in xrange(numFields-1):
					valList.append(m.group(i+1))
				key = '_'.join(valList)
				statList = m.group(numFields).split(',')
				if dict.has_key(key):
					for data in statList:
						data = data.replace(' ','')
						data = data.replace("'","")
						dict[key].append(data)
				else:
					dict[key] = []
					for data in statList:
						data = data.replace(' ','')
						data = data.replace("'","")
						dict[key].append(data)
	return(dict)


def computeData(dataDict):

        ###################################################################################################
        # This function computes the min, max and mean data from the list using the Chebyshev's algorithm #
        ################################################################################################### 
        for keys in dataDict.keys():
                dataSum = 0
                """Checking if all the list elements are equal"""
                if(len(set(dataDict[keys])) > 1):
                        for data in dataDict[keys]:
                                dataSum = dataSum+float(data)
                        dataMean = dataSum/len(dataDict[keys])
                        sdSum = 0
                        for val in dataDict[keys]:
                                sdSum = sdSum+(float(val)-dataMean)**2
                        sdMean = sdSum/(len(dataDict[keys])-1)
                        sDeviation = sdMean**0.5
                        minOutlierLimit = dataMean-(2*sDeviation)
                        maxOutlierLimit = dataMean+(2*sDeviation)
                        finalValList = []
                        finalSum = 0
                        for val in dataDict[keys]:
                                if((float(val) >= minOutlierLimit) and (float(val) <= maxOutlierLimit)):
                                        finalValList.append(val)
                                        finalSum = finalSum+float(val)
                        finalMean = '%.2f' %(finalSum/(len(finalValList)+1))
			
                        finalDataList = [min(dataDict[keys]),max(dataDict[keys]),finalMean]
                        dataDict[keys] = finalDataList
                else:
                        finalDataList = [min(dataDict[keys]),max(dataDict[keys]),dataDict[keys][0]]
                        dataDict[keys] = finalDataList


def main():
        parser = OptionParser(usage="usage: %prog [options] ",version="%prog 1.0")

        parser.add_option("-c", "--cycles",
                        action="store",
                        dest="cycles",
                        type="str",
                        help="Number of cycles to be executed...\
                              Options: 1:2:3 etc")

        parser.add_option("-m", "--machines",
                        action="store",
                        dest="machines",
                        type="str",
                        help="Remote Machines \n\
                        uname@machineip,uname:password@machineip")

	parser.add_option("-f", "--functions",
                        action="store",
                        dest="functions",
                        type="str",
                        help="Functions to be executed on the remote machines with the class name \n\
                        className1.function1,className2.function2")

	parser.add_option("-n", "--filename",
                        action="store",
                        dest="filename",
                        type="str",
                        help="File Name in which the specified function and class name are present")

	parser.add_option("-p", "--filepath",
                        action="store",
                        dest="filepath",
                        type="str",
                        help="Directory path where the python file is present")
	
	parser.add_option("-a", "--urlipaddress",
                        action="store",
                        dest="urlipaddr",
                        type="str",
                        help="Ip Address from which the GUI is launched")

	parser.add_option("-s", "--port",
                        action="store",
                        dest="port",
                        type="str",
                        help="Port on which the GUI is launched")

	
	parser.add_option("-d", "--profiledir",
                        action="store",
                        dest="profileDir",
                        type="str",
                        help="Firefox profile name")


        options, args = parser.parse_args()

	currentTime = time.ctime()
	currentTimeList = str(currentTime).split(' ')
	currentTime = '_'.join(currentTimeList)
	logFileName = 'loadTesting_'+str(currentTime)+'.log'	
	logging.basicConfig(filename='%s' %(logFileName),level=logging.DEBUG,format='%(asctime)s [%(levelname)s]: %(message)s')
        logging.info('Load Testing Process Started.....')

        if ((options.cycles is not None) and (options.machines is not None) and (options.functions is not None) and (options.filename is not None) and (options.filepath is not None) and (options.urlipaddr is not None) and (options.port is not None) and (options.profileDir is not None)):

		if ',' in options.machines:
			machineList = []
			machineDict = {}
			machineList = options.machines.split(',')
			numMachines = len(machineList)
			for machine in machineList:
				m = re.search('(.+?)@(.*)',machine)
				if m is not None:
					machineCredentials = m.group(1)
					machineIp = m.group(2)
					machineDict[machineIp] = []
					if ':' in machineCredentials:
						m = re.search('(.*?):(.*)',machineCredentials)
						if m is not None:
							userName = m.group(1)
							passWord = m.group(2)
							machineDict[machineIp].append(userName)
							machineDict[machineIp].append(passWord)
					else:
						machineDict[machineIp].append(machineCredentials)
		else:
			machineDict = {}
			numMachines = 1
			m = re.search('(.+?)@(.*)',options.machines)
                        if m is not None:
                         	machineCredentials = m.group(1)
                              	machineIp = m.group(2)
                             	machineDict[machineIp] = []
                            	if ':' in machineCredentials:
                                  	m = re.search('(.*?):(.*)',machineCredentials)
                                      	if m is not None:
                                        	userName = m.group(1)
                                             	passWord = m.group(2)
                                            	machineDict[machineIp].append(userName)
                                           	machineDict[machineIp].append(passWord)
                            	else:
                                	machineDict[machineIp].append(machineCredentials)

		if ',' in options.functions:
			functionsList = []
			functionsList = options.functions.split(',')
		else:
			functionsList = []
                        functionsList.append(options.functions)
	
		guiIpAddr = options.urlipaddr+':'+options.port
		perfConfDict = performanceConfigStats()		
		perfMachineSSHDict = connectRemoteMachines(perfConfDict)
		rMachineSSHDict = connectRemoteMachines(machineDict)

		fout = file('mylog.txt','w')
		for rSSHChild in rMachineSSHDict.keys():
			rMachineSSHDict[rSSHChild].logfile = fout

		############### Setting Up the test environment on the remote machines #################
		global threadSyncList
		threadSyncList = []
		threadList = []
		for rSSHChild in rMachineSSHDict.keys():	
			threadList.append(threading.Thread(target=remoteMachineEnvSetup, args=(rMachineSSHDict[rSSHChild],rSSHChild,machineDict,)))

        	if(len(threadList) > 0):
                	for thread in threadList:
                        	thread.start()

		threadControlVariable = 1
		while(threadControlVariable):
			if(len(threadSyncList) == len(threadList)):
				for thread in threadList:
                                	thread.join()
				threadControlVariable = 0

		#################### Running the Selenium Server on the Remote Machines ################
		global seleniumServerThreadSyncList
		seleniumServerThreadSyncList = []
		seleniumThreadList = []
		rMachineSeleniumSSHDict = connectRemoteMachines(machineDict)
		for rSSHChild in rMachineSeleniumSSHDict.keys():
			rMachineSeleniumSSHDict[rSSHChild].logfile=fout
			seleniumThreadList.append(threading.Thread(target=runSeleniumServer, args=(rMachineSeleniumSSHDict[rSSHChild],options.urlipaddr,machineDict,rSSHChild,options.profileDir,)))
		if(len(seleniumThreadList) > 0):
			for thread in seleniumThreadList:
				thread.start()

		threadControlVariable = 1
                while(threadControlVariable):
			if(len(seleniumServerThreadSyncList) == len(seleniumThreadList)):
				for thread in seleniumThreadList:
					thread.join()
				threadControlVariable = 0

		################## Replacing the ipaddress in the guiautomation file #####################
		for rSSHChild in rMachineSSHDict.keys():
			rMachineSSHDict[rSSHChild].sendline('sudo sed \'s/[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}:[0-9]\{1,\}/%s/g\' /tmp/LoadTesting/FunkLoad/VZWDemo/guiautomation.py > /tmp/LoadTesting/FunkLoad/VZWDemo/guiautomation_new.py' %(guiIpAddr))
			j = rMachineSSHDict[rSSHChild].expect(['[#\$] ','password '],timeout=300)
                	if j == 1:
                        	if(len(machineDict[machineIP]) > 1):
                                	rMachineSSHDict[rSSHChild].sendline(machineDict[rSSHChild][1])
                                	rMachineSSHDict[rSSHChild].expect('[#\$] ',timeout=300)

			rMachineSSHDict[rSSHChild].sendline('mv /tmp/LoadTesting/FunkLoad/VZWDemo/guiautomation_new.py /tmp/LoadTesting/FunkLoad/VZWDemo/guiautomation.py')
			rMachineSSHDict[rSSHChild].expect('[#\$] ')
		################ Running the python load on the remote machine ##################
		threadList = []
		for rSSHChild in rMachineSSHDict.keys():
			threadList.append(threading.Thread(target=pythonCommandGenerator, args=(rMachineSSHDict[rSSHChild],functionsList,options.filename,options.filepath,options.cycles,machineDict,rSSHChild,)))
			
		if(len(threadList) > 0):
                        for thread in threadList:
                                thread.start()

		################# Checking if the python load is running on  the remote machines #######################
		global remoteProcessMonotorThreadSyncList
        	remoteProcessMonitorThreadList = []
        	remoteProcessMonotorThreadSyncList = []
		pyLoadrMachineSSHDict = connectRemoteMachines(machineDict)		

		for rSSHChild in pyLoadrMachineSSHDict.keys():
			remoteProcessMonitorThreadList.append(threading.Thread(target=monitoRemoteMachineLoadRunStatus, args=(pyLoadrMachineSSHDict[rSSHChild],)))	
			
		if(len(remoteProcessMonitorThreadList) > 0):
			for thread in remoteProcessMonitorThreadList:
				thread.start()

		################# Copying Atlas and Flex log files per cycle from the load machines while python load is running ######################
		copyAtlasFlexLogFiles(options.cycles,machineDict,options.filepath,perfMachineSSHDict)	

		threadControlVariable = 1
                while(threadControlVariable):
                        if(len(remoteProcessMonotorThreadSyncList) == len(remoteProcessMonitorThreadList)):
                                for thread in threadList:
                                        thread.join()

				for thread in remoteProcessMonitorThreadList:
                                        thread.join()
                                threadControlVariable = 0
		del(pyLoadrMachineSSHDict)

		######################## Copying the CPU and Memory Stats from the remote machines #######################
		runCopyThreading(rMachineSSHDict,options.filepath,'cpuStats.txt')
		runCopyThreading(rMachineSSHDict,options.filepath,'memStats.txt')


		####################### Copying the performance time stat files from the remote machines ##################
		runCopyThreading(rMachineSSHDict,options.filepath,'perfTimeStats.txt')

		####################### Merging the CPU and Memory Stat Files ############################
		cpuStatDict = {}
		memStatDict = {}
		cpuStatDict = mergeStatFiles(rMachineSSHDict,cpuStatDict,'cpuStats.txt',4)
		memStatDict = mergeStatFiles(rMachineSSHDict,memStatDict,'memStats.txt',4)

		###################### Merging performance time stat files ##########################
		perfTimeStatDict = {}
		perfTimeStatDict = mergeStatFiles(rMachineSSHDict,perfTimeStatDict,'perfTimeStats.txt',3)

		finalperfTimeStatDict = {}
		for perfFunc in perfTimeStatDict.keys():
			li = perfFunc.split('_')
			key = '_'.join(li[0:len(li)-1])
			if(finalperfTimeStatDict.has_key(key)):
				for data in perfTimeStatDict[perfFunc]:
					finalperfTimeStatDict[key].append(data)
			else:
				finalperfTimeStatDict[key] = []
				for data in perfTimeStatDict[perfFunc]:
					finalperfTimeStatDict[key].append(data)

		updatedperfTimeStatDict = {}
		for key in finalperfTimeStatDict.keys():
			ukey = key+'_'+str(len(finalperfTimeStatDict[key]))
			updatedperfTimeStatDict[ukey] = finalperfTimeStatDict[key]

		################### Computing the performance time stats ####################
		computeData(updatedperfTimeStatDict)
		print"\nPerformance Time Stats for Various Functions"
		print"===================================================================================\n"
		print"%-45s%-20s%-15s%-15s%-15s%s" %("SCENARIO","CONCURRENT USERS","BEST TIMING","WORST TIMING","MEAN TIMING","STATUS")
		for key in updatedperfTimeStatDict.keys():
			valList = key.split('_')
			users = valList[-1]	
			func = '_'.join(valList[0:len(valList)-1])
			if(float(updatedperfTimeStatDict[key][-1]) > 16):
				print "%-45s%-20s%-15s%-15s%-15s%s" %(func,users,updatedperfTimeStatDict[key][0],updatedperfTimeStatDict[key][1],updatedperfTimeStatDict[key][2],"FAILED")
			else:
				print "%-45s%-20s%-15s%-15s%-15s%s" %(func,users,updatedperfTimeStatDict[key][0],updatedperfTimeStatDict[key][1],updatedperfTimeStatDict[key][2],"PASSED")

		#################### Computing CPU and Memory Stats #########################
		computeData(cpuStatDict)
		computeData(memStatDict)

		print"\nCPU And MEM Stats for various processes"
        	print"===========================================================================================\n"
        	print"%-20s%-10s%-20s%-10s%-10s%-10s%-10s%-10s%s" %("MACHINE","USERS","PROCESS","MIN CPU","MAX CPU","MEAN CPU","MIN MEM","MAX MEM","MEAN MEM")
        	for key in cpuStatDict.keys():
                	(server,process,users) = key.split('_')
			users = int(users)*numMachines
                	print "%-20s%-10s%-20s%-10s%-10s%-10s%-10s%-10s%s" %(server,str(users),process,str(cpuStatDict[key][0]),str(cpuStatDict[key][1]),str(cpuStatDict[key][2]),str(memStatDict[key][0]),str(memStatDict[key][1]),str(memStatDict[key][2]))
	
	else:
		print "Please enter values for all the parameters. Use --help option to check the correct format"


if __name__ == '__main__':
    main()

