from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Specific Tool Response Modifier")

        # Specify the tool(s) you want to listen to
        self.target_tools = [self._callbacks.TOOL_PROXY, self._callbacks.TOOL_REPEATER]

        # Register the extension for HTTP messages
        self._callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag in self.target_tools:
            if not messageIsRequest:
                # This is an HTTP response from the specified tool
                response = messageInfo.getResponse()

                # Modify the response by removing a specific header
                response_info = self._helpers.analyzeResponse(response)
                headers = list(response_info.getHeaders())

                # Define the header to remove (e.g., "Server")
                header_to_remove = "Content-Security-Policy"
                header_to_remove1 = "X-Content-Security-Policy"
                header_to_remove2 = "X-WebKit-CSP"
                # Remove the specified header
                headers = [header for header in headers if not header.startswith(header_to_remove + ":")]
                headers = [header for header in headers if not header.startswith(header_to_remove1 + ":")]
                headers = [header for header in headers if not header.startswith(header_to_remove2 + ":")]

                # Reconstruct the modified response
                modified_response = self._helpers.buildHttpMessage(headers, response[response_info.getBodyOffset():])

                # Set the modified response
                messageInfo.setResponse(modified_response)

# Create the Burp Extender
if __name__ in ['__main__', '__builtin__']:
    extender = BurpExtender()
