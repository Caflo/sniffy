def is_debugger_present(): # testing purposes
    gettrace = getattr(sys, 'gettrace', lambda : None) 
    return gettrace() is not None

import sys
from os import stat
from pathlib import Path
if not is_debugger_present():
    # These imports fail when being debugged, in particular it gives:
    # "RuntimeError: Exception has occurred: Cannot change thread mode after it is set"
    import winrt.windows.ui.notifications as notifications
    import winrt.windows.data.xml.dom as dom
import wmi

def get_network_interfaces():
    # TODO implement a cross-platform solution
    return get_network_interfaces_win()

def get_network_interfaces_win():
    c = wmi.WMI()
    qry = "select Name from Win32_NetworkAdapter where NetEnabled=True and NetConnectionStatus=2"

    lst = [o.Name for o in c.query(qry)]
    return lst

def get_network_interfaces_unix():
    raise NotImplementedError()

def cleanup_files(path, regex):
    for p in Path(path).glob(regex):
        p.unlink()


class Notifier:
    # TODO implement a cross-platform solution
    def __init__(self) -> None:
        self.app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe'
        self.nManager = notifications.ToastNotificationManager
        self.notifier = self.nManager.create_toast_notifier(self.app)

    def notify_sniffer_schedule(self, title, content):
        doc = self.__create_xml_string(title, content)
        #display notification
        self.notifier.show(notifications.ToastNotification(doc))

    def __create_xml_string(self, title, content):
        tString = f"""
        <toast>
            <visual>
            <binding template='ToastGeneric'>
                <text>{title}</text>
                <text>{content}</text>
            </binding>
            </visual>
            <actions>
            <action
                content="Dismiss"
                arguments="action=dismiss"/>
            </actions>        
        </toast>
        """
        # convert notification to an XmlDocument
        xDoc = dom.XmlDocument()
        xDoc.load_xml(tString)
        return xDoc