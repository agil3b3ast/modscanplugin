from preludecorrelator.pluginmanager import Plugin
import logging

CLASSIFICATION = 'PortScan'
print("### [ModScanPlugin] Log initialization ###")
logging.basicConfig(filename='~/modscanplugin.log',level=logging.DEBUG)
	
class ModScanPlugin(Plugin):
    def run(self, idmef):
        #print idmef
        logging.debug(str(idmef.get("alert.classification.text")))
        logging.debug('\n\n\n')
        source = IDMEF.get("alert.source(*).node.address(*).address")
		
		classification = IDMEF.get("alert.classification.text")
		for saddr in source:
		 if classification == CLASSIFICATION:
          ctx = Context("PORT_SCAN_STORM", { "expire": 120, "threshold": 150, "alert_on_expire": True }, update = True, idmef = idmef)
		  if ctx.getUpdateCount() == 0:
		   ctx.set("alert.correlation_alert.name", "Port Scan Storm Detected")
		   ctx.set("alert.classification.text", "PortScanStorm")
		   ctx.set("alert.assessment.impact.severity", "high")
    
    	