from preludecorrelator.pluginmanager import Plugin
import logging

ID_PORT_SCAN_DETECTED = "D1"
ID_PORT_SCAN_MONITORING = "D0"

PORT_SCAN_DETECTED = "Port Scan Detected"
PORT_SCAN_MONITORING = "Port Scan Monitoring"

print("### [ModScanPlugin] Log initialization ###")
logging.basicConfig(filename='~/modscanplugin.log',level=logging.DEBUG)


class ModScanPlugin(Plugin):
    
	def _PortScan(self, idmef):
        #print idmef
        logging.debug(str(idmef.get("alert.classification.text")))
        logging.debug('\n\n\n')
        source = IDMEF.get("alert.source(*).node.address(*).address")
		
		for saddr in source:
			ctx = Context("PORT_SCAN_STORM", { "expire": 30, "threshold": 5, "alert_on_expire": True }, update = True, idmef = idmef)
			if ctx.getUpdateCount() == 0:
				ctx.set("alert.correlation_alert.name", "Port Scan Storm Detected")
				ctx.set("alert.classification.text", "PortScanStorm")
				ctx.set("alert.assessment.impact.severity", "high")		
		
    def run(self, idmef):
		classification = IDMEF.get("alert.classification.text")
		if classification == PORT_SCAN_DETECTED:
			self._PortScan(idmef)			
    	