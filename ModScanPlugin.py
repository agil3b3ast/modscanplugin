from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.idmef import IDMEF
import logging

ID_PORT_SCAN_DETECTED = "D1"
ID_PORT_SCAN_MONITORING = "D0"

PORT_SCAN_DETECTED = "Port Scan Detected"
PORT_SCAN_MONITORING = "Port Scan Monitoring"

EVENT_ID = "event.id"

IP_SRC = "event.network.ip_src"
IP_DST = "event.network.ip_dst"

EXPIRATION = 30
THRESHOLD = 5

print("### [ModScanPlugin] Log initialization ###")
logging.basicConfig(filename='~/modscanplugin.log',level=logging.DEBUG)


class ModScanPlugin(Plugin):
    
	def _PortScan(self, idmef):
        #print idmef
        #logging.debug(str(idmef.get("alert.classification.text")))
        #logging.debug('\n\n\n')
        #source = IDMEF.get("alert.source(*).node.address(*).address")
		source = _getDataByMeaning(IP_SRC)
		dest = _getDataByMeaning(IP_DST)
		
		ctx = Context(("PORT_SCAN_STORM",source,dest), { "expire": EXPIRATION, "threshold": THRESHOLD, "alert_on_expire": True }, update = True, idmef = idmef)
		if ctx.getUpdateCount() == 0:
			ctx.set("alert.correlation_alert.name", "Port Scan Storm Detected")
			ctx.set("alert.classification.text", "PortScanStorm")
			ctx.set("alert.assessment.impact.severity", "high")		

    def _getDataByMeaning(self,meaning):
	    meanings = IDMEF.get("alert.additional_data(*).meaning")
		m_len = len(meanings)
		for m in xrange(m_len):
			if meanings[m] == meaning:
			    to_search = "alert.additional_data({}).data".format(m)
				d = IDMEF.get(to_search)
                return d
		return None	

    def run(self, idmef):
		if  _getDataByMeaning(EVENT_ID) == ID_PORT_SCAN_DETECTED:
			self._PortScan(idmef)			
