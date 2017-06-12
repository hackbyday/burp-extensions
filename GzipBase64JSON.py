#
# Burp Suite Extension - GZipBase64JSON
#
# This extension will
# - GZip compress and Base64 encode a JSON payload before its sent
# - Base64 decode and Gzip decompress a JSON payload on receipt
#

import sys
import gzip
from cStringIO import StringIO

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("GZIPBASE64")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
        return
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        
        # create a new instance of our custom editor tab
        return GzipBase64InputTab(self, controller, editable)
        
# 
# class implementing IMessageEditorTab
#

class GzipBase64InputTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        
        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)

        return
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "Gzip Base64 JSON"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):    
        if isRequest:
            r = self._helpers.analyzeRequest(content)
        else:
            r = self._helpers.analyzeResponse(content)
            
        for header in r.getHeaders():
            if header.startswith("Content-Type:"): 
                if header.split(":")[1].find("application/text") > 0: 
                    return True
                elif header.split(":")[1].find("text/html") > 0:
                    return True    
                else:
                    return False
                
        return False

    def setMessage(self, content, isRequest):
        if content is None:
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            if isRequest:
                r = self._helpers.analyzeRequest(content)
            else:
                r = self._helpers.analyzeResponse(content)
            
            body = content[r.getBodyOffset():].tostring()
        
            base64 = self._extender._helpers.base64Decode(body)
            data = self.decompress(base64)
            
            self._txtInput.setText(data)
            self._txtInput.setEditable(self._editable)
            
        self._currentMessage = content
        return

    def getMessage(self):   
        if self._txtInput.isTextModified():
            text = self._txtInput.getText()
            try:
                compressed = self.compress(text)
                data = self._extender._helpers.base64Encode(compressed)
            except:
                data = self._helpers.bytesToString(text)
                
            # Reconstruct request/response
            r = self._helpers.analyzeRequest(self._currentMessage)
                
            return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
        else:
            return self._currentMessage
        
    def isModified(self):
        
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        
        return self._txtInput.getSelectedText()

    def decompress(self, stringContent):
        try:
            buf = StringIO(stringContent)
            s = gzip.GzipFile(mode="r", fileobj=buf)
            content = s.read()
            return content
        except Exception as e:
            self.extender.stdout.println("error({0}): {1}".format(type(e), str(e)))
        return None

    def compress(self, content):
        stringContent = self.extender.helpers.bytesToString(content)
        try:
            buf = StringIO()
            s = gzip.GzipFile(mode="wb", fileobj=buf)
            s.write(stringContent)
            s.close()
            gzipContent = buf.getvalue()
            return gzipContent
        except Exception as e:
            self.extender.stdout.println("error({0}): {1}".format(type(e), str(e)))
        return None            
