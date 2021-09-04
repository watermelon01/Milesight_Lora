import requests
import os
import json
import threading
from time import sleep
from logger import logger
import urllib3
import sys
import base64
import codecs
import sqlite3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logLoraAPI = logger(__name__, file = True)
logData = logger("data", file = True)
stopThread = False
loraTimeout = 10

class loraAPI:
    def __init__(self,ip = "127.0.0.1", credentials = {"password": "password", "username": "apiuser"}):
        self.url = "https://" + ip + ":8080/api"
        self.credentials = credentials

    #generate_token generates a token on 
    def generate_token(self):
        try:
            token = requests.post(self.url+"/internal/login", json=self.credentials, verify=False, timeout = loraTimeout)
            if (token.status_code == 200):
                self.token = (token.text.split("\":\"")[1]).split("\"}")[0]
                logLoraAPI.info("token successfully generated")
            else:
                self.token = None
                logLoraAPI.error("token failed to generate")
        except: 
                logLoraAPI.error("Timeout Error")
     
    #check token checks if the token is still valid. Generates a new token if no token exists or if token has expired
    def check_token(self,section): 
        if (hasattr(self,'token') == False):
            logLoraAPI.info(["no token at", section, "generating new token"])
            self.generate_token()
            return 0
        else:
            content = {"Content-type":"application/json", "Authorization" : "Bearer " + self.token}
            application_url = self.url + "/applications?limit=1&offset=0"
            if (requests.get(application_url, headers = content,verify = False, timeout = loraTimeout).status_code != 200):
                logLoraAPI.info(["invalid token at",section,"generating new token"])
                self.generate_token()
               
    #gets all applications and saves them to applicationList
    def get_applications(self,limit = 10,offset = 0):
        self.check_token("get_applications")
        try:
            content = {"Content-type":"application/json", "Authorization" : "Bearer " + self.token}
            application_url = self.url + "/applications?limit=" + str(limit) + "&offset=" + str(offset)
            self.applicationList = json.loads(requests.get(application_url, headers = content,verify = False, timeout = loraTimeout).text)
            logLoraAPI.info("applications successfully retrieved")
        except: 
            logLoraAPI.error("applications not retrieved")
    
    #gets all devices and saves devices into a list.
    def get_devices(self,limit=10,offset=0):
        self.check_token("get_devices")
        try:
            content = {"Content-type":"application/json", "Authorization" : "Bearer " + self.token}
            devices_url = self.url + "/devices?limit=" + str(limit) + "&offset=" + str(offset)
            #Saves returned information in to deviceInfo
            self.deviceInfo = json.loads(requests.get(devices_url, headers = content,verify = False, timeout = loraTimeout).text)
            #Saves all device EUIs to deviceEUIList
            self.deviceEUIList = []; #init and clear deviceEUIList
            for i in range(0,int(self.deviceInfo["totalCount"])):
                if hasattr(self, 'deviceEUIList'): self.deviceEUIList.append(self.deviceInfo["devices"][i]["devEUI"])
                else: self.deviceEUIList = self.deviceInfo["devices"][i]["devEUI"]
            logLoraAPI.info("devices successfully retrieved")
        except:
            logLoraAPI.error("devices not retrieved")

    #sets up a HTTP stream of device information on the gateway
    def uplink_stream(self): 
        self.check_token("uplink_stream")
        if (hasattr(self,'deviceEUIList') == False):
            self.get_devices()

        #Sets up, uplink stream
        content = {"Content-type": "application/json", "Authorization": "Bearer " + self.token}
        uplink_url = self.url + "/devices/" + self.deviceEUIList[0] + "/data"
        logLoraAPI.info("Uplink stream started")
        self.httpStream = requests.get(uplink_url, headers = content,verify = False,stream=True)
        if self.httpStream.encoding is None: self.httpStream.encoding = 'utf-8'
        for line in self.httpStream.iter_lines(decode_unicode=True):
            global stopThread
            if line:
                line = uplinkDecoder.line_decoder(line)
                if line!= 0:
                    #Write code here
                    loraAPI.django_insert_data(line)
            if stopThread == True:
                break

        logLoraAPI.info("Uplink stream ended")

    #Puts the HTTP stream on its own thread
    def uplink_stream_thread(self):
        t = threading.Thread(target = self.uplink_stream)
        t.start()

    #Closes HTTPstream thread
    def close_threads(self):
        global stopThread
        stopThread = True

    def django_insert_data(jsonData):
        #opens database
        con = sqlite3.connect('db.sqlite3')
        cur = con.cursor()

        deveui = jsonData['devEUI']
        data = json.dumps(jsonData)

        #searches if entry exists
        cur.execute("SELECT * FROM api_loradata WHERE deveui = ?",(deveui,))
        entry = cur.fetchall()

        #Checks if entry exists, updates if entry does, creates a new entry if it doesn't
        if entry != []:
            print("entry")
            cur.execute("UPDATE api_loradata SET data = ? WHERE deveui = ?",(data,deveui))
        else:
            print("no entry")
            cur.execute("INSERT INTO api_loradata (deveui,data) VALUES (?,?)",(deveui,data))

        #closes database
        con.commit()
        con.close()            

    def downlink_queue_time(self,time = 1200, mode = 'all'):
        self.check_token("downlink_queue")
        self.get_devices()
        content = {"Content-type":"application/json", "Authorization" : "Bearer " + self.token}

        logInterval = hex(time).replace('0x',"")

        if (len(logInterval) > 4): 
            logInterval = hex(1200).replace('0x',"")
        while (len(logInterval) != 4):
            logInterval = "0" + logInterval
        setLogTime = "ff03" + logInterval[-2:] + logInterval[:-2]
        setLogTime = codecs.encode(codecs.decode(setLogTime,"hex"),'base64').decode()

        if (mode == 'all'): 
            for device in self.deviceEUIList:
                downlink_url = self.url + "/devices/" + device + "/queue"
                payload  = {"confirmed" : False, "data" : setLogTime, "devEUI" : device,"fPort":85}
                response = requests.post(downlink_url, json=payload, headers = content, verify=False, timeout = loraTimeout)
                logLoraAPI.info(["set report interval of device: ",device,"to",time,"seconds"])
                sleep(5)
                print(response)

    #Clears all system logs
    def clear_logs(self):
        logLoraAPI.clear_logs()


#Uplink decoder class decodes uplink messages, based on the Milesight IoT suitee
class uplinkDecoder:
    @staticmethod
    #Decodes HTTP Stream
    def line_decoder(message): 
        message = json.loads(message)
        payload = json.loads(message['result']['payloadJSON'])
        #Converts payload from base64 to hex
        if (message['result']['type'] == 'uplink'):
            try:
                #PYTHON 2 IMPLEMENTATION
                data = base64.b64decode(payload['data']).encode('hex') 
            except: 
                #PYTHON 3 IMPLEMENTATION
                data = base64.b64decode(payload['data']).hex()
            #em300 Decoder Check
            em300Decode = uplinkDecoder.decode_EM300_TH(data)
            if (em300Decode):
                data = em300Decode
            #Tries to decode as a uc500
            else: 
                uc500Decode = uplinkDecoder.decode_UC500(data)
                if uc500Decode:
                    data = uc500Decode
                else: 
                    return 0
            #format JSON
            devEUI = payload['devEUI']
            deviceName = payload['deviceName']
            #Save message to dictionary - JSON format
            jsonData = {"name" : deviceName,"devEUI" : devEUI,"data" : data,"time" : str(datetime.now())}
            return jsonData
        else:
            msgType = message['result']['type']
            return "found message of type " + msgType

    def decode_EM300_TH(data):
        decoded = {}
        byte_array = bytearray.fromhex(data)
        i = 0 
        while i < (len(byte_array)):
            channelId = byte_array[i]
            channelType = byte_array[i+1]
            i+=2
            #battery
            if (channelId == 0x01 and channelType == 0x75):
                decoded['battery'] = byte_array[i] 
                i += 1
            #Temperature
            elif (channelId == 0x03 and channelType == 0x67):
                decoded['temperature'] = ((byte_array[i+1] << 8) + byte_array[i])/10
                i += 2
            #humidity
            elif (channelId == 0x04 and channelType == 0x68):
                decoded['humidity'] = byte_array[i]/2
                i += 1
            else: 
                break

        return decoded

    def decode_UC500(data):
        decoded = {}
        byte_array = bytearray.fromhex(data)
        i = 0 
        while i < (len(byte_array)):
            channelId = byte_array[i]
            channelType = byte_array[i+1]
            i+=2
            #battery
            if (channelId == 0x01 and channelType == 0x75):
                decoded['battery'] = byte_array[i] 
                i+=1

            #GPIO1
            elif(channelId == 0x03 and channelType != 0xc8):
                decoded['gpio1'] = 'on' if byte_array[i] == 0 else 'off'
                i+=1

            #GPIO2
            elif(channelId == 0x04 and channelType != 0xc8):
                decoded['gpio2'] = 'on' if byte_array[i] == 0 else 'off'
                i+=1

            #Pulse Counter 1 
            elif (channelId == 0x03 and channelType == 0xc8):
                decoded['counter1'] = (byte_array[i+3] << 24) + (byte_array[i+2] << 16) + byte_array[i+1] << 8 +byte_array[i]
                i+=4

            #Pulse Counter 2
            elif (channelId == 0x04 and channelType == 0xc8):
                decoded['counter2'] = (byte_array[i+3] << 24) + (byte_array[i+2] << 16) + byte_array[i+1] << 8 +byte_array[i]
                i+=4

            #ADC 1
            elif (channelId == 0x05):
                adc = {}
                adc['cur'] = (byte_array[i+1] << 8) + byte_array[i]
                adc['min'] = (byte_array[i+3] << 8) + byte_array[i+2]
                adc['max'] = (byte_array[i+5] << 8) + byte_array[i+4]
                adc['avg'] = (byte_array[i+7] << 8) + byte_array[i+6]
                decoded['adc1'] = adc
                i+=8

            #ADC 2
            elif (channelId == 0x06):
                adc = {}
                adc['cur'] = (byte_array[i+1] << 8) + byte_array[i]
                adc['min'] = (byte_array[i+3] << 8) + byte_array[i+2]
                adc['max'] = (byte_array[i+5] << 8) + byte_array[i+4]
                adc['avg'] = (byte_array[i+7] << 8) + byte_array[i+6]
                decoded['adc2'] = adc
                i+=8

            #MODBUS 
            elif (channelId == 0xFF and channelType == 0x0E):
                modbusChannelId = byte_array[i]
                packageType = byte_array[i+1]
                i+=2
                dataType = packageTpye & 7
                channel = "channel " + str(int(modbusChannelId) - 6)
                if (dataType == 0):
                    decoded[channnel] = 'on' if byte_array[i] else 'off'
                    i+=1
                    break
                elif (dataType == 1):
                    decoded[channel] = byte_array[i]
                    i+=1
                    break
                elif(dataType == 3):
                    decoded[channel] = (byte_array[i+1] << 8) + byte_array[i]
                    i+=2
                    break
                elif(dataType == 6):
                    decoded[channel] = (byte_array[i+3] << 24) + (byte_array[i+2] << 16) + byte_array[i+1] << 8 + byte_array[i]
                    i+=4
                    break
                elif(dataType == 7):
                    bits = (byte_array[i+3] << 24) | byte_array[i+2] | byte_array[i+2] | byte_array[0]
                    sign = 1 if (bits>>31) == 0 else -1
                    e = bits >> 23 & 0xFF
                    m = (bits & 0x7fffff) if e == 0 else (bits & 0x7fffff) | 0x800000 
                    modbus[channel] = sign*m*(2**(e-150))
                    i+=4
                    break

            #Passes if Modbus data is undefined
            elif (channelId == 0xFF):
                if (byte_array[i] >= 7 and byte_array[i] <= 22): 
                    channel = "channel " + str(int(byte_array[i])-6)
                    decoded[channel] = 'undefined'
                    i+=1
                else:
                    i+=1

        return decoded
