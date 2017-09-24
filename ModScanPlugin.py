import logging

print("### [ModScanPlugin] Log initialization ###")
logging.basicConfig(filename='~/modscanplugin.log',level=logging.DEBUG)

class ModScanPlugin(Plugin):
    def run(self, idmef):
        logging.debug(str(idmef.get("alert.classification.text")))
        logging.debug('\n\n\n')
