from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
import zlib

# Valid second bytes for zlib header (first byte is always 0x78)
# CMF byte encodes compression method + window size; these cover all standard levels
ZLIB_SECOND_BYTES = {0x01, 0x5E, 0x9C, 0xDA, 0x20, 0x7D, 0xBB, 0xF9}


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Zlib Decoder")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.printOutput("[+] Zlib Decoder loaded")

    def createNewInstance(self, controller, editable):
        return ZlibTab(self, controller, editable)


class ZlibTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        self._editor = extender._callbacks.createTextEditor()
        self._editor.setEditable(editable)
        self._currentMessage = None
        self._isRequest = False

    def getTabCaption(self):
        return "Zlib Decoded"

    def getUiComponent(self):
        return self._editor.getComponent()

    # ------------------------------------------------------------------ helpers

    def _splitMessage(self, content, isRequest):
        """Return (header_bytes, body_bytes, body_offset)."""
        if isRequest:
            info = self._helpers.analyzeRequest(content)
        else:
            info = self._helpers.analyzeResponse(content)
        offset = info.getBodyOffset()
        body = bytes(bytearray(content[offset:]))
        return offset, body

    def _isZlib(self, body):
        return (len(body) >= 2
                and bytearray(body)[0] == 0x78
                and bytearray(body)[1] in ZLIB_SECOND_BYTES)

    def _decompress(self, data):
        # try standard zlib, raw deflate, gzip in order
        for wbits in (15, -15, 47):
            try:
                return bytearray(zlib.decompress(data, wbits))
            except Exception:
                continue
        return bytearray(b"[!] Decompression failed — not a recognised zlib/deflate/gzip stream")

    def _compress(self, data):
        # re-compress with the same default level (zlib level 6)
        return bytearray(zlib.compress(bytes(bytearray(data)), 6))

    # ------------------------------------------------------------------ IMessageEditorTab

    def isEnabled(self, content, isRequest):
        if not content or len(content) == 0:
            return False
        try:
            _, body = self._splitMessage(content, isRequest)
            return self._isZlib(body)
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        if content is None:
            self._editor.setText(None)
            self._currentMessage = None
            return

        self._currentMessage = content
        self._isRequest = isRequest

        _, body = self._splitMessage(content, isRequest)
        self._editor.setText(self._decompress(body))

    def getMessage(self):
        # If the tab is read-only or unchanged, return the original message unchanged.
        if not self._editable or not self._editor.isTextModified():
            return self._currentMessage

        # Re-compress the edited plaintext and splice it back into the message.
        try:
            edited_plain = self._editor.getText()
            new_body = self._compress(edited_plain)
        except Exception as e:
            self._extender._callbacks.printError("Re-compress error: " + str(e))
            return self._currentMessage

        offset, _ = self._splitMessage(self._currentMessage, self._isRequest)
        return bytes(bytearray(self._currentMessage[:offset]) + new_body)

    def isModified(self):
        return self._editor.isTextModified()

    def getSelectedData(self):
        return self._editor.getSelectedText()
