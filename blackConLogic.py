from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtCore import *
from blackCon import Ui_MainWindow
import urllib.parse
import socket
import requests
import re
import sys, traceback

class BlackConLogic(Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.window = None
        self.theradpool = QThreadPool()

    def ShowWindow(self):
        window = QMainWindow()
        self.window = window
        window.show()
        self.ui.setupUi(window)
        self.initialize()

    def initialize(self):
        self.ui.checkButton.clicked.connect(lambda : self.startCheckProcessWorker())
        self.ui.helpAction.triggered.connect(lambda: self.setHelp())
        self.ui.exitAction.triggered.connect(lambda: self.exit())
  
    def startCheckProcessWorker(self):
        self.ui.resultsBox.setText("[*] Wait for results ...")
        worker = Worker(self.checkProcess)
        worker.signals.result.connect(self.print_output)
        self.theradpool.start(worker)

    def print_output(self, s):
        self.ui.resultsBox.setText(s)

    # get info 
    def extractDomainName(self, url):
        parsedUrl = urllib.parse.urlparse(url)
        return parsedUrl.netloc
        
    def getIpByDomain(self, domain):
        host = socket.gethostbyname(domain)
        return host

    def getIpByUrl(self, url):
        host = urllib.parse.urlparse(url).hostname
        addr = socket.gethostbyname(host)
        return addr

    def getUrlLocation(self, url):
        try:
            ip = self.getIpByUrl(url)
            api_url = f"http://ip-api.com/json/{ip}"
            response = requests.get(api_url)
            data = response.json()
            return f"[*] Locatino : {data['city']}, {data['regionName']}, [{data['country']}]\n[*] Location on the map :  https://www.google.com/maps/place/{data['lat']},{data['lon']}"
        except:
            return "[!] Error in getting location"
    
    # input checking
    def is_link(self, url):
        regex = r"(http|https)://[a-zA-Z0-9@:%._\\+~#?&//=]"
        if re.match(regex, url):
            return True
        else:
            return False

    # checking process 
    def linkAnalysis(self, url):
        try:
            response = self.response
            results = "\n[*] Analysis :"
            if response.status_code == 200:
                urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', response.text)
                filesPatern = r'\b[A-Za-z0-9._-]+\.txt|\b[A-Za-z0-9._-]+\.del|\b[A-Za-z0-9._-]+\.img|\b[A-Za-z0-9._-]+\.jpg|\b[A-Za-z0-9._-]+\.exe|\b[A-Za-z0-9._-]+\.js|\b[A-Za-z0-9._-]+\.py|\b[A-Za-z0-9._-]+\.js|\b[A-Za-z0-9._-]+\.pdf|\b[A-Za-z0-9._-]+\.svg|\b[A-Za-z0-9._-]+\.ico|\b[A-Za-z0-9._-]+\.gif|\b[A-Za-z0-9._-]+\.css'
                files = re.findall(filesPatern, response.text)
                results += "\n\t======================\n\tURLS IN BODY RSPONSE\n\t======================"
                for bodyUrl in urls:
                    results += f"\n\t{bodyUrl}"
                results += "\n\t======================\n\tFILE NAMES IN BODY RSPONSE\n\t======================"
                for file in files:
                    results += f"\n\t{file}"
                return results
            else:
                return "[!] \nError with body analysis"
        except:
            return "\n[!] There is no response"

    def checkUrlhausList(self, url):
        try:
            url_api = "https://urlhaus.abuse.ch/downloads/json_recent/"
            response = requests.get(url_api)
            if response.status_code == 200:
                api = response.json()
                for id, urlsData in api.items():
                    for urlData in urlsData:
                        if url == urlData["url"]:
                            data = ""
                            for tag, value in urlData.items():
                                data += f"\t{tag} : {value}\n"
                            return f"[!] [{url}] Found in /urlHaus/ black list not secure" + "\n\tURL DATA:\n" + f"{data}"
                        else:
                            continue
                return f"[*] [{url}] Not in /urlHaus/ black list "
        except:
            return "[!] Error with 'urlHasu' checking "
        
    def checkIps(self, url):
        try:
            try:
                domain = self.extractDomainName(url)
            except:
                return "[!] Error extracting domain name"
            webIp = self.getIpByDomain(domain)
            urlIp = self.getIpByUrl(url)
            if webIp == urlIp:
                return f"[*] Domain : {domain}\n\t{webIp} :: {domain} \n\t{urlIp} :: {url}\n[*] IP matching True"
            else:
                return f"[*] Domain : {domain}\n\t{webIp} :: {domain} \n\t{urlIp} :: {url}\n[!] IP not matching False"
        except:
            return "[!] Error checking the address "
        
    def getUrlResponse(self, url):
        response = requests.get(url)
        self.response = response
        if response:
            responseHeader = response.headers
            headerData = "\n\t========\n\tHEADER\n\t========\n"
            for key, value in responseHeader.items():
                headerData += f"\t{key} : {value}\n"
            if self.ui.displayBodyOption.isChecked():
                bodyData = "\t========\n\tBODY\n\t========\n" + response.text
            else:
                bodyData = "" 
            Data = "\n[*] Response :" + headerData + bodyData
            return Data
        else:
            return "\n[!] Error get response "
        
    def checkProcess(self):
        try:
            url = self.ui.urlInput.text()
            if self.is_link(url):
                ceckIpsResult = self.checkIps(url)
                getUrlLocationResult = self.getUrlLocation(url)
                checkUrlhausListresult = self.checkUrlhausList(url)
                allResults = f"{ceckIpsResult}\n{getUrlLocationResult}\n{checkUrlhausListresult}"
                if self.ui.getResponseOption.isChecked():
                    try:
                        response = self.getUrlResponse(url)
                        allResults += response
                    except:
                        allResults += "\n[!] Error with get response function"
                if self.ui.urlAnalysisOption.isChecked():
                    analysisResults = self.linkAnalysis(url)
                    allResults += analysisResults
                return allResults
            else:
                return "[!] Invalid url"
        except:
            return "[!] Checking error check your connection"
        
    def setHelp(self):
        help = """
        BLACKCON : \n
It is a tool used to detect whether the link is safe to enter or not

How it works:

First, we compare the original domain IP with the last IP to which the link is linked to verify that there is no request transfer to an external IP

Second, we bring the geographical location of the link IP to verify its location

Third, we compare the link's compatibility with any link in the database of dangerous links that are constantly updated

Fourth, the tool can analyze the link content in a simple way to bring the links or file names used in the response body

Note:

1- When confirming the response fetch option, we capture the link content

2- It is true that the tool provides you with the ability to test and examine suspicious links, but nevertheless, we do not prefer to enter links that are not reliable and suspicious

"""
        self.ui.resultsBox.setText(help)
        
    def exit(self):
        QCoreApplication.instance().quit()  

class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @pyqtSlot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit() 

class WorkerSignals(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    progress = pyqtSignal(int)

if __name__ == '__main__':
    app = QApplication([sys.argv])
    blackConObj = BlackConLogic()
    blackConObj.ShowWindow()
    app.exec()
