import logging

print("### [ModScanPlugin] Log initialization ###")
logging.basicConfig(filename='~/modscanplugin.log',level=logging.DEBUG)

class ModScanPlugin(Plugin):
    def run(self, idmef):
        logging.debug(str(idmef))
        logging.debug('\n\n\n')
