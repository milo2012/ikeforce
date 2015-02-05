import commands,re,sys,argparse,os

hostNo = ""

wordList=[]
wordList.append("groupnames.dic")
wordList.append("english_len3-7-vpn.txt")
'''
wordList.append("3lu.markov")
wordList.append("english_len3-7-toggle-firstcase.txt")
wordList.append("3lu.markov.vpn	")
wordList.append("english_len3-7-vpn-toggle-firstcase.txt")
wordList.append("3lu.min3.markov	")
wordList.append("3lu.min3.markov.vpn")
wordList.append("english_len3-7.txt")
wordList.append("3lu.txt")
wordList.append("4l.markov")
wordList.append("4lu.markov")
wordList.append("4u.markov")
wordList.append("4u.markov.vpn")
wordList.append("4u.min4.markov")
'''

def runCommand(fullCmd):
    try:
        return commands.getoutput(fullCmd)
    except:
        return "Error executing command %s" %(fullCmd)

def extractTransform(str):
	r = re.compile('SA=\((.*?)\)')
	m = r.search(str)
	if m:
    		results = m.group(1)
		return results

def bruteVPN(hostNo):
	cmd = "sudo ike-scan "+hostNo
	results = runCommand(cmd)	

	resultsList = (extractTransform(results)).split(" ")
	encType = resultsList[0].replace("Enc=","")
	hashType = resultsList[1].replace("Hash=","")
	dhGroup = resultsList[2].replace("Group=2:","")
	authType = resultsList[3].replace("Auth=","")

	transformSetResults = ""
	
	transformSetList=[]
	encType = encType.lower()
	if encType=="des":
		transformSetResults += "1"
	elif encType=="idea":
		transformSetResults += "2"
	elif encType=="blowfish":
		transformSetResults += "3"
	elif encType=="rc5":
		transformSetResults += "4"
	elif encType=="3des":
		transformSetResults += "5"
	elif encType=="cast":
		transformSetResults += "6"
	elif encType=="aes":
		transformSetResults += "7"
	else:
		print "Encryption type not in preset list"

	hashType=hashType.lower() 
	if hashType=="md5":
		transformSetResults += " 1"
	if hashType=="sha1":
		transformSetResults += " 2"
	if hashType=="tiger":
		transformSetResults += " 3"
	if hashType=="sha2=256":
		transformSetResults += " 4"
	if hashType=="sha2-384":
		transformSetResults += " 5"
	if hashType=="sha2-512":
		transformSetResults += " 6"

	authType=authType.lower() 
	if authType=="psk":
		transformSetResults += " 1"
	if authType=="dss":
		transformSetResults += " 1"
		transformSetList.append("2") 
	if authType=="rsa_sig":
		transformSetResults += " 2"
		transformSetList.append("3") 
	if authType=="rsa_enc":
		transformSetResults += " 3"
		transformSetList.append("4") 
	if authType=="rsa_revenc":
		transformSetResults += " 4"
		transformSetList.append("5") 
	if authType=="hybrid_rsa":
		transformSetResults += " 5"
		transformSetList.append("64221") 
	if authType=="xauth_psk":
		transformSetResults += " 6"
	
	dhGroup = dhGroup.lower() 
	if dhGroup=="modp768":
		transformSetResults += " 1"
	if dhGroup=="modp1024":
		transformSetResults += " 2"
	if dhGroup=="ec2n155":
		transformSetResults += " 3"
	if dhGroup=="ec2n185":
		transformSetResults += " 4"
	if dhGroup=="modp1536":
		transformSetResults += " 5"

	transformSetResults = transformSetResults.strip()
	transformSetResultsList =  transformSetResults.split(" ")
	if transformSetResultsList>3:
		skip=False
		count=0
		while(skip==False or count<(len(wordList)-1)):
			for word in wordList:
				print "- Using word list: "+word.strip()
				ikeforceCmd = "sudo python ikeforce.py "+hostNo+" -e -s 1 -w wordlists/"+word+" -t "+transformSetResults
				print ikeforceCmd
				results = runCommand(ikeforceCmd)
				if "is not included yet" in results:
					print results
					skip=True
				else:
					print results
				count+=1
	else:
		print "Unable to detect the transform set"

if __name__== '__main__':
	parser= argparse.ArgumentParser()
    	parser.add_argument('-i', dest='hostNo', action='store', help='[IP address of VPN server]')
    	parser.add_argument('-iL', dest='nmapFile', action='store', help='[File containing list of VPN servers]')

   	options= parser.parse_args()
	if options.hostNo:
		hostNo = (options.hostNo).strip()
		print "- Testing: "+str(hostNo)
		bruteVPN(options.hostNo)
	if options.nmapFile:
		if os.path.exists(options.nmapFile):
			with open(options.nmapFile) as f:
				ipList = f.readlines()
				for hostNo in ipList:
					hostNo = hostNo.strip()
					print "- Testing: "+str(hostNo)
					bruteVPN(hostNo)
