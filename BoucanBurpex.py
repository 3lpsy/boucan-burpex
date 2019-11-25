#!/usr/bin/env python2

from burp import IBurpExtender
from burp import ITab
from burp import IProxyListener
from burp import IHttpRequestResponse
from javax.swing.table import AbstractTableModel
from java.util import ArrayList
from java.lang import Runnable
from java.awt import Dimension
from javax import swing
import threading
import sys
import json
from urlparse import urlparse
from StringIO import StringIO
from httplib import HTTPResponse
from injections import DEFAULT_INJECTIONS
import time
import md5
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

DEFAULT_USER_AGENT = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.28) Gecko/00000000 Firefox/30.0.00"
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "TRACK"]

DEBUG_ENABLED=False
BEACON_ENABLED=True
BEACON_NAME="bcand"

callbacks = None
helpers = None


class FakeSocket:
    def __init__(self, response_str):
        self._file = StringIO(response_str)

    def makefile(self, *args, **kwargs):
        return self._file


class PyRunnable(Runnable):
    def __init__(self, target, *args, **kwargs):
        self.target = target
        self.args = args
        self.kwargs = kwargs

    def run(self):
        self.target(*self.args, **self.kwargs)


class RequestBuilder:

    def __init__(self, method, url, headers):
        self._method = method
        self._url = urlparse(url)
        self._headers = headers # list of tuples

    def addBearer(self, token):
        hval = "Bearer " + str(token)
        self._headers.append(("Authorization", hval))

    def build(self):
        requestString = StringIO()
        requestString.write(self._method.upper())
        requestString.write(" ")
        requestString.write(self._url.path)
        requestString.write(" HTTP/1.1\r\n")
        requestString.write("HOST: ")
        requestString.write(str(self._url.hostname))
        requestString.write("\r\n")
        requestString.write(
            DEFAULT_USER_AGENT + "\r\n"
        )

        # headers are list of tuples
        for headerTuple in self._headers:
            requestString.write(headerTuple[0] + ": " + str(headerTuple[1]))
            requestString.write("\r\n")

        requestString.write("\r\n\r\n")

        # print "Request: " + str(requestString.getvalue())
        builtRequest = map(lambda x: ord(x), requestString.getvalue())
        requestString.close()
        return builtRequest

    
class ApiClient(object):
    def __init__(self, api_url, api_token):
        self._api_url = api_url
        self._api_token = api_token

    def get_zones(self):
        # print "Building request"
        requestBuilder = RequestBuilder("get", self.url("/zone"), [("Accept", "application/json")])
        requestBuilder.addBearer(self._api_token)
        request = requestBuilder.build()
        # print "Hostname: " + str(self.hostname())
        # print "Port: " + str(self.port())
        # print "HTTPS?: " + str(self.is_https())
        # print "Invoking request"
        try:
            response = callbacks.makeHttpRequest(self.service(), request)
            status = int(response.getStatusCode())
            if status == 200:
                return self.get_json(response)["zones"]
            else:
                if status == 0:
                    print "[!] HTTP Error. Coud not get Zones. Status code was 0. The server may not be reachable. Confirm API_URL."
                else:
                    print "[!] HTTP Error. Could not get Zones. Code: " + str(status)

        except Exception as e:
            print "[!] HTTP Error. Could not get Zones: " + str(e)

        return []


    def get_json(self, response):
        res_bytes = response.getResponse()  # byte[]
        if not res_bytes:
            print "[!] Failed to get json for Response. Response has not bytes"
            return {}
        res_str = str(helpers.bytesToString(res_bytes))
        source = FakeSocket(res_str)
        res_obj = HTTPResponse(source)
        res_obj.begin()
        # print "Reading response object"
        res_text = res_obj.read()
        try:
            res_data = json.loads(res_text)
        except Exception as e:
            print "[!] Failed to convert to json: " + str(res_text)
            res_data = {}
        return res_data

    def url(self, path):
        return self._api_url + path

    def port(self):
        port = self.parsed_url().port
        if port:
            return int(port)
        elif self.parsed_url().scheme == "https":
            return 443
        else:
            return 80

    def is_https(self):
        return self.parsed_url().scheme == "https"

    def hostname(self):
        hostname = self.parsed_url().hostname
        if hostname:
            return hostname
        # print "No hostname on parsed url. using netloc"
        return self.parsed_url().netloc

    def parsed_url(self):
        return urlparse(self._api_url)

    def service(self):
        return helpers.buildHttpService(
            str(self.hostname()), self.port(), self.is_https()
        )


# this is straight from burp collaborator, not useful until we introduce payloads to api
class MetaRequest:

    # proxyMessage: IInterceptedProxyMessage
    def __init__(self, proxyMessage):
        self.request = proxyMessage.getMessageInfo()
        self.burpId = proxyMessage.getMessageReference()
        self.timestamp = int(round(time.time() * 1000))

    # response: IHttpRequestResponse
    def overwriteRequest(self, response):
        self.request = response

    def getRequest(self):
        return self.request

    def getBurpId(self):
        return self.burpId

    def getTimestamp(self):
        return self.timestamp


class Injector(IProxyListener):
    def __init__(self):
        self._injections = []
        self._zones = []
        self._enabled = False

    def setInjections(self, injections):
        self._injections = injections

    def setZones(self, zones):
        self._zones = zones
    
    def getZones(self):
        return self._zones

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False
        
    def isEnabled(self):
        return self._enabled

    def getInjections(self):
        enabledInjections = []
        # injection = injectionMethod,injectionType,injectionTarget,injectionValue
        for s in self._injections:
            if not s[0] == "#":
                enabledInjections.append(s)
        return enabledInjections

    # request: messageInfo: IHttpRequestResponse, IRequestInfo
    def injectPayloads(self, messageInfo, requestInfo):
        print "[*] Injecting Payloads..."
        host = requestInfo.url.getHost()
        port = requestInfo.url.port
        https = 1 if 'https' in requestInfo.url.getProtocol() else 0
        request = messageInfo.getRequest()
        baseHeaders = requestInfo.getHeaders()
        body = request[requestInfo.getBodyOffset():]
        service = messageInfo.getHttpService()
        method = requestInfo.getMethod()

        # path = requestInfo.url.getPath()
        # TODO: add referer?
        # TODO: set/replace Cache-Control with "no-transform"
        for zone in self.getZones():
            if DEBUG_ENABLED:
                print "[.] Injection Target: " + zone["domain"]

            # injection = injectionMethod, injectionType,injectionTarget,injectionValue
            for injection in self.getInjections():
                # rebuild header list

                injectionSet = injection.split(",")
                if len(injectionSet) != 4:
                    print "[!] Invalid Length for Injection: " + injection
                    continue

                injectionMethod = injectionSet[0]
                injectionType = injectionSet[1]
                injectionTarget = injectionSet[2]
                injectionValue = injectionSet[3]

                if injectionMethod != "*" and injectionMethod.upper() != method.upper():
                    # print "Invalid method for injection: " + injection
                    continue

                # use .format() ?
                injectionValue = injectionValue.replace('%s', zone["domain"])

                if DEBUG_ENABLED:
                    print "[.] Injection Value: " + injectionValue

                targetHost = ""
                for h in baseHeaders:
                    if h.upper().startswith("HOST:"):
                        targetHost = h.split(':', 1)[1]
                if len(targetHost) < 1:
                    # print "[!] No Target Host Found for Request. Skipping injection: " + injection
                    continue
                
                injectionValue = injectionValue.replace('%h', targetHost)
                
                injectionDesc = injectionType + "/" + injectionTarget + "/" + injectionValue
                # print "Injecting Payloads For Injection: " + injectionDesc
                
                # adds a simple short 12 character hash to the requests
                # this makes it unique so it'll show up sitemap
                # would prefer to be able to append to proxyhistory, but i guess fun isn't allowed

                if BEACON_ENABLED:
                    m = md5.new()
                    m.update(injectionDesc)
                    beacon = str(m.hexdigest())[0:12]
                    # print "Adding Beacon to Request: " + beacon
                    beaconParam = helpers.buildParameter(BEACON_NAME, beacon, 0)

                if injectionType == "param":
                    if BEACON_ENABLED:
                        if DEBUG_ENABLED:
                            print "[.] Attaching beacon: " + BEACON_NAME + "=" + beacon
                        request = helpers.addParameter(request, beaconParam)

                    # IParameter.PARAM_URL == 0
                    param = helpers.buildParameter(injectionTarget, injectionValue, 0)
                    modifiedRequest = helpers.removeParameter(request, param)
                    modifiedRequest = helpers.addParameter(modifiedRequest, param)

                elif injectionType == "header":
                    # the header becaon must be added differently
                    headers = []
                    replaced = False
                    for h in baseHeaders:
                        splitHeaders = h.split(":", 1)
                        headerName = splitHeaders[0]
                        if len(splitHeaders) < 2:
                            if h.split(" ")[0].upper() in HTTP_METHODS:
                                # do some stuff with the path maybe?
                                dummy = 1
                            else:
                                print"[!] No Header Value for Header: " + h
                            headers.append(h)
                        else:
                            headerVal = splitHeaders[1]
                            if headerVal.upper() == injectionTarget.upper():
                                headers.append(headerName + ":" + injectionValue)
                            else:
                                headers.append(h)
                    if not replaced:
                        headers.append(injectionTarget + ": " + injectionValue)
                    modifiedRequest = helpers.buildHttpMessage(headers, body)
                    # add the beacon, after making the body
                    if BEACON_ENABLED:
                        if DEBUG_ENABLED:
                            print "[.] Attaching beacon: " + BEACON_NAME + "=" + beacon
                        modifiedRequest = helpers.addParameter(modifiedRequest, beaconParam)

                else:
                    print "[!] Unrecognized Injection Type for Injection: " + injection
                    continue

                if DEBUG_ENABLED:
                    print "[.] Making injection request for: " + injectionDesc

                # print "Sending Injection Request..."
                httpRequestResponse = callbacks.makeHttpRequest(
                    service, modifiedRequest
                )
                if not httpRequestResponse.getResponse():
                    print "[!] Failed to get response for injection. Response has no bytes"
                else:
                    # print "Adding RR to SiteMap"
                    if DEBUG_ENABLED:
                        print "[.] Adding requests/reseponse to sitemap for: " + injectionDesc

                    callbacks.addToSiteMap(httpRequestResponse)
                    # request = str(helpers.bytesToString(httpRequestResponse.getRequest()))
                    # print "REQUEST:"
                    # print request
                    # response = str(helpers.bytesToString(httpRequestResponse.getResponse()))
                    # print "RESPONSE:"
                    # print response
                    if DEBUG_ENABLED:
                        print "-----"
                        print ""

    def processProxyMessage(self, messageIsRequest, message):
        global callbacks
        global helpers

        if self.isEnabled():
            # print "Injector: Processing Proxy Message"
            messageInfo = message.getMessageInfo()  # IHttpRequestResponse

            # check if in scope
            requestInfo = helpers.analyzeRequest(
                messageInfo.getHttpService(), messageInfo.getRequest()
            )  # IRequestInfo

            if not callbacks.isInScope(requestInfo.getUrl()):
                # print "Message not in scope"
                return

            # print "Message is in scope"

            # MetaRequest is a burp collaborator thing
            # not useful yet, we may store "payloads"
            metaRequest = MetaRequest(message)
            self.injectPayloads(messageInfo, requestInfo)
        else:
            print "Injector is disabled. Skipping..."
        


class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, _callbacks):
        global callbacks
        global helpers
        callbacks = _callbacks
        self._callbacks = _callbacks
        helpers = callbacks.getHelpers()
        self._helpers = helpers
        sys.stdout = callbacks.getStdout()
        self._callbacks.setExtensionName("Boucan")
        self._panel = self.buildPanel()
        self.loadZones()

        print "Adding Boucan Tab"
        self._callbacks.addSuiteTab(self)

        print "Building Injector"
        self._injector = Injector()
        self._injector.setInjections(self._injections)
        self._injector.setZones(self._zones)

        print "Registering Injector"
        self._callbacks.registerProxyListener(self._injector)

        print "Extender Callback Registration Complete"
        return

    def disableInjector(self, event):
        self._statusLabel.setText("Status: Disabled")
        self._injector.disable()

    def enableInjector(self, event):
        self._statusLabel.setText("Status: Enabled")
        self._injector.enable()

    def buildPanel(self):
        print "Building Panel..."
        panel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()

        # print "Creating Status Label"
        self._statusLabelBox = swing.Box.createHorizontalBox()
        self._statusLabel = swing.JLabel("Status: Disabled")
        self._statusLabelBox.add(self._statusLabel)
        boxVertical.add(self._statusLabelBox)

        # print "Adding Status Change Button"
        disableInjectorBox = swing.Box.createHorizontalBox()
        disableInjectorButton = swing.JButton(
            "Disable", actionPerformed=self.disableInjector
        )
        disableInjectorBox.add(disableInjectorButton)
        boxVertical.add(disableInjectorBox)

        enableInjectorBox = swing.Box.createHorizontalBox()
        enableInjectorButton = swing.JButton(
            "Enable", actionPerformed=self.enableInjector
        )
        enableInjectorBox.add(enableInjectorButton)
        boxVertical.add(enableInjectorBox)

        # print "Creating API URL Label..."
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Enter API URL"))
        boxVertical.add(boxHorizontal)

        # print "Creating API URL Text Field..."
        boxHorizontal = swing.Box.createHorizontalBox()
        self._apiUrl = swing.JTextField(self.loadApiUrl(), 30)
        boxHorizontal.add(self._apiUrl)
        boxVertical.add(boxHorizontal)

        # print "Creating API Token Label..."
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Enter API Token"))
        boxVertical.add(boxHorizontal)

        # print "Creating API Token Text Field..."
        boxHorizontal = swing.Box.createHorizontalBox()
        self._apiToken = swing.JTextArea()
        apiTokenOuput = swing.JScrollPane(self._apiToken)
        apiTokenOuput.setPreferredSize(Dimension(250, 125))
        self._apiToken.setText(self.loadApiToken())
        self._apiTokenOuput = apiTokenOuput
        boxHorizontal.add(self._apiTokenOuput)
        boxVertical.add(boxHorizontal)

        self._zones = []
        # print "Creating Zones Output Box"
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Loaded Zones (Output)"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._zonesLoaded = swing.JTextArea()
        zonesLoaded = swing.JScrollPane(self._zonesLoaded)
        zonesLoaded.setPreferredSize(Dimension(250, 125))
        boxHorizontal.add(zonesLoaded)
        boxVertical.add(boxHorizontal)

        # print "Adding Update Button"
        boxHorizontal = swing.Box.createHorizontalBox()
        updateConfButton = swing.JButton(
            "Update Configuration / Zones", actionPerformed=self.updateConfEvent
        )
        boxHorizontal.add(updateConfButton)
        boxVertical.add(boxHorizontal)

        # self._payloads = []
        # print "Creating Payloads Output Box"
        # boxHorizontal = swing.Box.createHorizontalBox()
        # boxHorizontal.add(swing.JLabel("Submitted Payloads (Output)"))
        # boxVertical.add(boxHorizontal)
        # boxHorizontal = swing.Box.createHorizontalBox()
        # self._payloadsSubmitted = swing.JTextArea()
        # payloadsSubmitted = swing.JScrollPane(self._payloadsSubmitted)
        # payloadsSubmitted.setPreferredSize(Dimension(250, 125))
        # boxHorizontal.add(payloadsSubmitted)
        # boxVertical.add(boxHorizontal)

        self._injections = DEFAULT_INJECTIONS
        # print "Creating Injections Box"
        injectionsHorizontalLabel = swing.Box.createHorizontalBox()
        injectionsHorizontalLabel.add(swing.JLabel("Injections List"))
        boxVertical.add(injectionsHorizontalLabel)
        injectionsHorizontalTextArea = swing.Box.createHorizontalBox()
        self._injectionsList = swing.JTextArea()
        injectionsHorizontalTextAreaScrollPane = swing.JScrollPane(self._injectionsList)
        injectionsHorizontalTextAreaScrollPane.setPreferredSize(Dimension(250, 350))
        injectionsHorizontalTextArea.add(injectionsHorizontalTextAreaScrollPane)
        boxVertical.add(injectionsHorizontalTextArea)
        self.copyInjectionsToTextArea()

        # print "Adding Update Injections Button"
        updateInjectionsButtonHorizontal = swing.Box.createHorizontalBox()
        updateInjectionsButton = swing.JButton(
            "Update Injections", actionPerformed=self.updateInjectionsEvent
        )
        updateInjectionsButtonHorizontal.add(updateInjectionsButton)
        boxVertical.add(updateInjectionsButtonHorizontal)

        # print "Adding Vertical Box to Panel..."
        panel.add(boxVertical)
        return panel

    def copyInjectionsToTextArea(self):
        print "Copying Injections from _injects to TextArea "
        self._injectionsList.setText("")
        for i in range(len(self._injections)):
            injection = self._injections[i]
            self._injectionsList.append(injection)
            if len(self._injections) > 1 and i != (len(self._injections) - 1):
                self._injectionsList.append("\r\n")

    def copyInjectionsFromTextArea(self):
        injectionsListText = self._injectionsList.text
        injections = []
        print "Reading Injections from TextArea"
        for i in injectionsListText.splitlines():
            if i:
                injections.append(i)

        print "Updating Injections on Base Extender"
        self._injections = injections
        print "Updating Injections on Injector"
        self._injector.setInjections(self._injections)
        self.copyInjectionsToTextArea()

    def updateInjectionsEvent(self, button):
        self.copyInjectionsFromTextArea()

    def updateConfEvent(self, button):
        self.updateConf()

    def updateConf(self):
        api_url = self._apiUrl.text
        self.saveApiUrl(api_url)
        api_token = self._apiToken.text
        self.saveApiToken(api_token)
        self.loadZonesLater()

    def loadZonesLater(self):
        print "Loading zones..."
        thread = threading.Thread(target=self.loadZones, args=())
        thread.start()

    def loadZones(self):
        api_url = self._apiUrl.text
        api_token = self._apiToken.text
        if api_url and api_token:
            # print "Requesting zones from api"
            zones = self.api().get_zones()
            self._zones = zones
            # print "Clearing loaded zones"
            self._zonesLoaded.setText("")
            for i in range(len(zones)):
                zone = zones[i]
                domain = str(zone["domain"])
                # print "Appending zone " + domain
                self._zonesLoaded.append(domain)
                if len(zones) > 1 and i != (len(zones) - 1):
                    self._zonesLoaded.append("\r\n")
            self._zonesLoaded.setEditable(False)
            # print "Zones loaded"
        else:
            print "[!] Zones not loaded. No API Token or URL. Or no zones in Boucan."
        return ""

    def getTabCaption(self):
        return "Boucan"

    def getUiComponent(self):
        return self._panel

    def loadApiUrl(self):
        return self._callbacks.loadExtensionSetting("api_url")

    def saveApiUrl(self, val):
        return self._callbacks.saveExtensionSetting("api_url", val)

    def loadApiToken(self):
        return self._callbacks.loadExtensionSetting("api_token")

    def saveApiToken(self, val):
        return self._callbacks.saveExtensionSetting("api_token", val)

    def api(self):
        api_url = self._apiUrl.text
        api_token = self._apiToken.text
        # print "Building API Client"
        return ApiClient(api_url, api_token)


# Always at the end
try:
    FixBurpExceptions()
except:
    pass
