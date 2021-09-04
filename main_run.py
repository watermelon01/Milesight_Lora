import loraModule
import threading
from time import sleep


timeInterval = 30
loraGateway = loraModule.loraAPI("192.168.0.150")
loraGateway.clear_logs()
#loraGateway.downlink_queue_time(timeInterval)
loraGateway.uplink_stream_thread()

try:
	while True:
		print("Main Loop running")
		#loraGateway.downlink_queue_time()
		sleep(timeInterval)

except:
	print("threads Closing")
	loraGateway.close_threads()
	sleep(5)
	print("threads active", threading.enumerate())