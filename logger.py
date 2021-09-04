import logging
import os

class logger(object):
	logFormat = logging.Formatter("%(asctime)s: %(levelname)s : %(name)s : %(message)s")

	def __init__(self,name,stream = False, file=False,logLevel = logging.INFO): 
		self.log = self._get_logger(name,stream,file,logLevel)

	def _get_logger(self,name,stream,file,logLevel):
		#set log name and information
		log = logging.getLogger(name)
		log.setLevel(logLevel)
		log.name = name

		#enables file Handler
		if (file == True): 
			fileHandler = logging.FileHandler(name + '.log')
			fileHandler.setFormatter(self.logFormat)
			log.addHandler(fileHandler)

		#enables stream handler
		if (stream == True):
			streamHandler = logging.StreamHandler()
			streamHandler.setFormatter(self.logFormat)
			log.addHandler(streamHandler)
		
		#sets logging level above all logging types.
		if (stream == False and file == False): 
			log.setLevel(100) 
		return log

	#List_handler allows multiple messages to be read. List_handler is 
	#Automatically called if a list is passed in as an input 
	def list_handler(self,list,type):
		message = ""
		for string in list: 
			message = message + str(string) + " "
		exec("self." + type + "('" + message + "')")

	def debug(self,message):
		if (isinstance(message, list) == True):
			self.list_handler(message,'debug')
		else: 
			self.log.debug(message)

	def info(self,message):
		if (isinstance(message, list) == True):
			self.list_handler(message,'info')
		else: 
			self.log.info(message)

	def warning(self,message):
		if (isinstance(message, list) == True):
			self.list_handler(message,'warning')
		else: 
			self.log.warning(message)

	def error(self,message):
		if (isinstance(message, list) == True):
			self.list_handler(message,'error')
		else:
			self.log.error(message)

	def critical(self,message):
		if (isinstance(message, list) == True):
			self.list_handler(message,'critical')
		else:
			self.log.critical(message)

	def clear_logs(self):
		with open (self.log.name + '.log', 'w'):
			pass

	@staticmethod
	def log_Multiple(inputs,message,logType = 'info'):
		if (type(inputs) != list):
			pass
		else: 
			try:
				for x in inputs:
					if logType == 'debug':
						x.debug(message)
					elif logType == 'warning': 
						x.warning(message)
					elif logType == 'error':
						x.error(message)
					elif logType == 'critical':
						x.critical(message)
					else: 
						x.info(message)
			except: 
				print("ERROR: Argument not of type <Logger>")


#JUST FOR TESTING PURPOSES
if __name__ == '__main__': 
	loraLog = logger("loraLog",stream = True)

	a = 'first message'
	b = 'second message'
	c = 'third message'
	d = 'fourth message'

	loraLog.info([a,b,c,d])

	loraLog.info(["Added","functionality","to","parse","multiple","inputs"])
