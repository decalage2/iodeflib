"""
IODEFlib

a python library to create, parse and edit cyber incident reports using the
IODEF XML format (RFC 5070).

Project website: http://www.decalage.info/python/iodeflib

Copyright (c) 2011-2012, Philippe Lagadec (http://www.decalage.info)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

__version__ = '0.07'

#------------------------------------------------------------------------------
# CHANGELOG:
# 2011-10-23 v0.01 PL: - first version
# 2012-01-24 v0.02 PL: - added get methods to XML mapper, Assessment, Impact
# 2012-02-15 v0.03 PL: - added AdditionalData, HistoryItem
# 2012-02-17 v0.04 PL: - added pretty_print option when lxml is available
# 2012-03-28 v0.05 PL: - added parse_file
# 2012-04-06 v0.06 PL: - added get_sources/targets
# 2012-04-11 v0.07 PL: - added System.get_addresses, Incident.add_system

#------------------------------------------------------------------------------
# TODO:
# ? add copyright notice for RFC5070 text, or rewrite class descriptions?
# + add class for multilingual strings, but also allow simple str
# + methods to extract/iter all AdditionalData elements with a specific dtype
#   and/or formatid
# + use python datetime for all timestamps, use dateutil for ISO8601 parsing:
##    import dateutil.parser
##    yourdate = dateutil.parser.parse(datestring)
#   (just store a list of datetime attrib names in XML mapper, for transparent
#   automatic conversion)
# + to make classes suitable to support IODEF extensions, add class variables
#   to store subelement classes. (e.g. IncidentClass in IODEF_Document)
#   => can be overridden when subclassing to implement phishing extension, for
#   example.
# - method to verify XML schema before parsing (and option in parse function)
#   and after serializing to XML
# ? provide dictionaries with enums and descriptions from RFC 5070?


#--- IMPORTS ------------------------------------------------------------------

import logging

#import xml.etree.ElementTree as ET
LXML = False
try:
    # lxml: best performance for XML processing
    import lxml.etree as ET
    LXML = True
except ImportError:
    try:
        # Python 2.5+: batteries included
        import xml.etree.cElementTree as ET
    except ImportError:
        try:
            # Python <2.5: standalone ElementTree install
            import elementtree.cElementTree as ET
        except ImportError:
            raise ImportError, "lxml or ElementTree are not installed, "\
                +"see http://codespeak.net/lxml "\
                +"or http://effbot.org/zone/element-index.htm"


#--- CONSTANTS ----------------------------------------------------------------

# an empty IODEF document (with proper namespaces)
EMPTY_IODEF = """<IODEF-Document version="1.00" lang="en"
  xmlns="urn:ietf:params:xml:ns:iodef-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:schema:iodef-1.0"/>
"""

# IODEF XML namespace (with curly brackets for ElementTree)
NS = '{urn:ietf:params:xml:ns:iodef-1.0}'

# XML tags, including namespace
TAG_Incident    = NS+'Incident'
TAG_IncidentID  = NS+'IncidentID'
TAG_ReportTime  = NS+'ReportTime'
TAG_DetectTime  = NS+'DetectTime'
TAG_StartTime   = NS+'StartTime'
TAG_EndTime     = NS+'EndTime'
TAG_Description = NS+'Description'
TAG_Assessment  = NS+'Assessment'
TAG_Impact      = NS+'Impact'
TAG_AdditionalData = NS+'AdditionalData'
TAG_History     = NS+'History'
TAG_HistoryItem = NS+'HistoryItem'
TAG_DateTime    = NS+'DateTime'
TAG_EventData   = NS+'EventData'
TAG_Flow        = NS+'Flow'
TAG_System      = NS+'System'
TAG_Node        = NS+'Node'
TAG_NodeName    = NS+'NodeName'
TAG_Address     = NS+'Address'



#=== FUNCTIONS ================================================================

def get_logger(name, level=logging.DEBUG):
    """
    Create a logger object which logs up to DEBUG on the console only.
    The goal is not to change settings of the root logger, to avoid messing
    with the main application.
    If a logger exists with same name, reuse it. (Else it would have duplicate
    handlers and messages would be doubled.)
    """
    # First, test if there is already a logger with the same name, else it
    # will generate duplicate messages (due to duplicate handlers):
    if name in logging.Logger.manager.loggerDict:
        #NOTE: another less intrusive but more "hackish" solution would be to
        # use getLogger then test if its effective level is not default.
        logger = logging.getLogger(name)
        # make sure level is OK:
        logger.setLevel(level)
        return logger
    # define a Handler which writes level messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(level)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # get a new logger:
    logger = logging.getLogger(name)
    # add the console handler to the logger
    logger.addHandler(console)
    logger.setLevel(level)
    #print 'effective level for logger "%s":' % name, logging.getLevelName(logger.getEffectiveLevel( ))
    return logger


# default logger object:
log = get_logger('iodeflib')
debug = log.debug


def _new_list(option):
    """
    helper function to create a new object attribute in a constructor method:
    if option is None, returns an empty list, else option.
    usage:
        def __init__(self, attr1):
            self.attr1 = _new_list(attr1)
    """
    #TODO: create a list as [option] if option is not a list?
    if option is None:
        return []
    else:
        return option


def _make_list (obj):
    """
    helper function to convert any object to a list:
        - if obj is already a list, return it as-is
        - if obj is a str or unicode, return [obj]
        - if obj is None, return []
        - if obj is any other object type, return list(obj)
    (this trick is required because list(str) returns a list of single
    characters instead of a list containing one string, and list(list) creates
    a new copy of the list)
    """
    if isinstance(obj, list):
        return obj
    elif isinstance(obj, basestring):
        return [obj]
    elif obj is None:
        return []
    else:
        return list(obj)


#=== CLASSES ==================================================================

class _XMLMapper (object):
    """
    base class providing helper methods to convert Python objects to/from XML
    """

    #TODO:
    # ? use unicode() instead of str()?
    # - list of attributes to be converted to/from datetime automatically

    def _set_xml_attribs(self, elem, *attrib_names, **kw_attrib_names):
        """
        for each attrib name, add an xml attribute to elem (XML Element object),
        using the value from the self object attribute with same name
        (self.attrib), unless it is None.
        For attributes provided as key='value' pairs, key is the Python attribute
        name (self.key), value is the XML attribute name.
        """
        for attrib in attrib_names:
            value = getattr(self, attrib, None)
            if value is not None:
                elem.set(attrib, str(value))
        for attrib, xml_attrib  in kw_attrib_names.items():
            value = getattr(self, attrib, None)
            if value is not None:
                elem.set(xml_attrib, str(value))

    def _set_xml_tag(self, elem, tag, attrib, *attrib_names, **kw_attrib_names):
        """
        Append a new XML tag to elem (XML Element object), set its text using
        the python attribute named attrib. This is done ONLY if attrib is not
        None, or if attrib_names and kw_attrib_names are not empty.
        Then optionally set XML attributes using _set_xml_attribs.
        Return the XML element that was created, or None.
        """
        if attrib is not None:
            value = getattr(self, attrib, None)
        else:
            value = None
        if value is not None or attrib_names or kw_attrib_names:
            subelem = ET.SubElement(elem, tag)
            subelem.text = value
            self._set_xml_attribs(subelem, *attrib_names, **kw_attrib_names)
            return subelem
        else:
            return None

    def _set_xml_taglist(self, elem, tag, attrib):
        """
        Append new subelements to elem (XML Element object) with the given XML
        tag, set their text using the values of the list stored in self.attrib.
        """
        values = getattr(self, attrib, [])
        for value in values:
            subelem = ET.SubElement(elem, tag)
            subelem.text = value

    def _set_xml_subclass(self, elem, attrib):
        """
        Append new subelements to elem (XML Element object) with the given XML
        tag, serializing the objects of the list stored in self.attrib.
        """
        objects = getattr(self, attrib, [])
        for obj in objects:
            elem.append(obj.to_xml())

    def _get_xml_attribs(self, elem, *attrib_names, **kw_attrib_names):
        """
        for each attrib name, get the corresponding xml attribute from elem
        (XML Element object), and store the value in the current object (self)
        attribute with same name.
        If the xml attribute is absent, the value will be None.
        For attributes provided as key='value' pairs, key is the Python
        attribute name (self.key), value is the XML attribute name.
        """
        for attrib in attrib_names:
            # get XML attrib or None
            value = elem.get(attrib, None)
            # set the object attrib
            setattr(self, attrib, value)
        for attrib, xml_attrib in kw_attrib_names.items():
            # get XML attrib or None
            value = elem.get(xml_attrib, None)
            # set the object attrib
            setattr(self, attrib, value)

    def _get_xml_tag(self, elem, tag, attrib, *attrib_names, **kw_attrib_names):
        """
        Find the first subelement of elem (XML Element object) with the given
        XML tag, store its text value in the attribute named attrib of the
        current object (self).
        If the subelement does not exist, self.attrib is set to None.
        Then optionally get XML attributes using _get_xml_attribs.
        Return the XML element that was found, or None.
        """
        subelem = elem.find(tag)
        if subelem is not None:
            # XML tag found, set object.attrib to its text value:
            if attrib:
                setattr(self, attrib, subelem.text)
            # then store its attributes in the object attribs:
            self._get_xml_attribs(subelem, *attrib_names, **kw_attrib_names)
        else:
            # no XML tag found, set object.attrib to None:
            if attrib:
                setattr(self, attrib, None)
        return subelem

    def _get_xml_taglist(self, elem, tag, attrib):
        """
        Find all subelements of elem (XML Element object) with the given
        XML tag, store their text value in the attribute named attrib of the
        current object (self) as a list of strings.
        If no matching subelement is found, self.attrib is set to an empty list.
        """
        # start with an empty list
        l = []
        for subelem in elem.findall(tag):
            l.append(subelem.text)
        # store the list in self.attrib:
        setattr(self, attrib, l)


    def _get_xml_subclass(self, elem, tag, attrib, Class):
        """
        Find all subelements of elem (XML Element object) with the given
        XML tag, parse each and create a corresponding Class object,
        stored in the attribute named attrib of the current object (self) as a
        list of Class objects.
        If no matching subelement is found, self.attrib is set to an empty list.
        """
        #TODO: get XML tag from subclass?
        # start with an empty list
        l = []
        # parse each corresponding tag, and create a Class object, stored in list
        for subelem in elem.findall(tag):
            l.append(Class(from_xml=subelem))
        # store the list in self.attrib:
        setattr(self, attrib, l)



#------------------------------------------------------------------------------
class AdditionalData (_XMLMapper):
    """
    class storing additional custom data

    attributes:
    - data: str
    - dtype: enum of str
    - ext_dtype: str
    - formatid: str
    - meaning: str
    - restriction: enum of str
    """

    def __init__(self, data=None, dtype=None, ext_dtype=None,
        formatid=None, meaning=None, restriction=None,
        from_xml=None):
        self.data = data
        self.dtype = dtype
        self.ext_dtype = ext_dtype
        self.formatid = formatid
        self.meaning = meaning
        self.restriction = restriction
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        xml = ET.Element(TAG_AdditionalData)
        if self.data is not None:
            xml.text = self.data
        self._set_xml_attribs(xml, 'dtype', 'formatid',
            'meaning', 'restriction', ext_dtype='ext-dtype')
        return xml

    def from_xml(self, xml):
        self._get_xml_attribs(xml, 'dtype', 'formatid',
            'meaning', 'restriction', ext_dtype='ext-dtype')
        self.data = xml.text

    def __str__(self):
        return 'AdditionalData dtype=%s ext_dtype=%s formatid=%s meaning=%s data="%s"' % (
            self.dtype, self.ext_dtype, self.formatid, self.meaning, self.data)


#------------------------------------------------------------------------------
class Address (_XMLMapper):
    """
    The Address class represents a hardware (layer-2), network (layer-3),
    or application (layer-7) address.

    attributes:
    - address: str
    - category: enum of str
    - ext_category: str
    - vlan_name: str
    - vlan_num: str (int in RFC 5070)
    """

    def __init__(self, address=None, category='ipv4-addr', ext_category=None,
        vlan_name=None, vlan_num=None,
        from_xml=None):
        """
        constructor for Address class
        - see class attributes
        - from_xml: Element object (XML) to be parsed
        """
        self.address = address
        self.category = category
        self.ext_category = ext_category
        self.vlan_name = vlan_name
        self.vlan_num = vlan_num
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        xml = ET.Element(TAG_Address)
        if self.address is not None:
            xml.text = self.address
        self._set_xml_attribs(xml, 'category', 'vlan_name',
            'vlan_num', ext_category='ext-category')
        return xml

    def from_xml(self, xml):
        self._get_xml_attribs(xml, 'category', 'vlan_name',
            'vlan_num', ext_category='ext-category')
        self.address = xml.text

    def __str__(self):
        return 'Address address=%s category=%s ext_category=%s vlan_name=%s vlan_num=%s' % (
            self.address, self.category, self.ext_category, self.vlan_name,
            self.vlan_num)


#------------------------------------------------------------------------------
class System (_XMLMapper):
    """
    The System class describes a system or network involved in an event.
    The systems or networks represented by this class are categorized
    according to the role they played in the incident through the
    category attribute.  The value of this category attribute dictates
    the semantics of the aggregated classes in the System class.  If the
    category attribute has a value of "source", then the aggregated
    classes denote the machine and service from which the activity is
    originating.  With a category attribute value of "target" or
    "intermediary", then the machine or service is the one targeted in
    the activity.  A value of "sensor" dictates that this System was part
    of an instrumentation to monitor the network.

    This iodeflib.System class also contains the IODEF Node class, because there
    is a one-to-one mapping:
    The Node class names a system (e.g., PC, router) or network.

    attributes:
    - category: enum of str, source/target/intermediary/sensor
    - ext_category: str
    - descriptions: list of str
    - interface: str
    - spoofed: enum of str
    - additional_data: AdditionalData
    - restriction: enum of str
    - node_datetime: str
    - node_location: str
    - node_names: list of str
    - node_addresses: list of Address objects
    - node_roles: list of NodeRole objects
    """

    # class variables for subelement classes:
    # can be overridden when implementing IODEF extensions
    AdditionalDataClass = AdditionalData
    AddressClass = Address


    def __init__(self, category=None, ext_category=None, descriptions=None,
        interface=None, spoofed=None, restriction=None,
        additional_data=None,
        node_datetime=None, node_location=None, node_names=None,
        node_addresses=None,
        from_xml=None):
        """
        constructor for System class
        - see class attributes
        - from_xml: Element object (XML) to be parsed
        """
        self.category = category
        self.ext_category = ext_category
        self.descriptions = _new_list(descriptions)
        self.interface = interface
        self.spoofed = spoofed
        self.restriction = restriction
        self.additional_data = _new_list(additional_data)
        self.node_datetime = node_datetime
        self.node_location = node_location
        self.node_names = _new_list(node_names)
        self.node_addresses = _new_list(node_addresses)
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        xml = ET.Element(TAG_System)
        self._set_xml_attribs(xml, 'category', 'restriction', 'interface',
            'spoofed', ext_category='ext-category')
        self._set_xml_taglist(xml, TAG_Description, 'descriptions')
        self._set_xml_subclass(xml, 'additional_data')
        node = self._set_xml_tag(xml, TAG_Node, None, 'node_datetime', 'node_location')
        self._set_xml_taglist(node, TAG_NodeName, 'node_names')
        self._set_xml_subclass(node, 'node_addresses')
        return xml

    def from_xml(self, xml):
        self._get_xml_attribs(xml, 'category', 'restriction', 'interface',
            'spoofed', ext_category='ext-category')
        self._get_xml_taglist(xml, TAG_Description, 'descriptions')
        # parse AdditionalData elements:
        self._get_xml_subclass(xml, TAG_AdditionalData, 'additional_data', self.AdditionalDataClass)
        node = self._get_xml_tag(xml, TAG_Node, None, 'node_datetime', 'node_location')
        self._get_xml_taglist(node, TAG_NodeName, 'node_names')
        self._get_xml_subclass(node, TAG_Address, 'node_addresses', self.AddressClass)

    def __str__(self):
        return 'System category=%s ext_category=%s interface=%s spoofed=%s node_location=%s node_names=%s node_addresses=%s descriptions: %s' % (
            self.category, self.ext_category, self.interface, self.spoofed,
            self.node_location, ','.join(self.node_names),
            ','.join(self.get_addresses()),
            ', '.join(self.descriptions))

    def get_addresses (self):
        """
        return list of addresses for this system/node (e.g. all IP addresses)
        The result is a list of strings containing the address attribute of
        all the Address objects for this System/Node.
        """
        return [addr.address for addr in self.node_addresses]
##        result = []
##        for addr in self.node_addresses:
##            result.append(addr.address)
##        return result


#------------------------------------------------------------------------------
class Flow (_XMLMapper):
    """
    The Flow class groups related the source and target hosts.

    attributes:
    - systems: list of System objects
    """

    # class variables for subelement classes:
    # can be overridden when implementing IODEF extensions
    SystemClass = System


    def __init__(self, systems=None, from_xml=None):
        """
        constructor for Flow class
        - systems: list of System objects
        - from_xml: Element object (XML) to be parsed
        """
        self.systems = _new_list(systems)
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        """
        convert the object to XML, return an Element object
        """
        xml = ET.Element(TAG_Flow)
        self._set_xml_subclass(xml, 'systems')
        return xml

    def from_xml(self, xml):
        """
        parse an Element object (XML) to populate this object
        """
        # parse System elements:
        self._get_xml_subclass(xml, TAG_System, 'systems', self.SystemClass)

    def __str__(self):
        return 'Flow'


    def get_sources (self):
        """
        return list of systems with category='source'
        """
        result = []
        for system in self.systems:
            if system.category == 'source':
                result.append(system)
        return result


    def get_targets (self):
        """
        return list of systems with category='target'
        """
        result = []
        for system in self.systems:
            if system.category == 'target':
                result.append(system)
        return result


#------------------------------------------------------------------------------
class EventData (_XMLMapper):
    """
    The EventData class describes a particular event of the incident for
    a given set of hosts or networks.  This description includes the
    systems from which the activity originated and those targeted, an
    assessment of the techniques used by the intruder, the impact of the
    activity on the organization, and any forensic evidence discovered.

    attributes:
    - description: list of str
    - start_time: str
    - detect_time: str
    - end_time: str
    - restriction: enum of str
    - additional_data: list of AdditionalData objects
    - flows: list of Flow objects
    """

    # class variables for subelement classes:
    # can be overridden when implementing IODEF extensions
    AdditionalDataClass = AdditionalData
    FlowClass = Flow


    def __init__(self, descriptions=None, start_time=None, detect_time=None,
        end_time=None, restriction=None,
        additional_data=None, flows=None,
        from_xml=None):
        """
        constructor for EventData class
        """
        self.descriptions = _new_list(descriptions)
        self.start_time = start_time
        self.detect_time = detect_time
        self.end_time = end_time
        self.restriction = restriction
        self.additional_data = _new_list(additional_data)
        self.flows = _new_list(flows)
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        """
        convert the object to XML, return an Element object
        """
        xml = ET.Element(TAG_EventData)
        self._set_xml_attribs(xml, 'restriction')
        self._set_xml_tag(xml, TAG_StartTime, 'start_time')
        self._set_xml_tag(xml, TAG_DetectTime, 'detect_time')
        self._set_xml_tag(xml, TAG_EndTime, 'end_time')
        self._set_xml_taglist(xml, TAG_Description, 'descriptions')
        self._set_xml_subclass(xml, 'additional_data')
        self._set_xml_subclass(xml, 'flows')
        return xml

    def from_xml(self, xml):
        """
        parse an Element object (XML) to populate this object
        """
        self._get_xml_attribs(xml, 'restriction')
        self._get_xml_tag(xml, TAG_StartTime, 'start_time')
        self._get_xml_tag(xml, TAG_DetectTime, 'detect_time')
        self._get_xml_tag(xml, TAG_EndTime, 'end_time')
        self._get_xml_taglist(xml, TAG_Description, 'descriptions')
        # parse AdditionalData elements:
        self._get_xml_subclass(xml, TAG_AdditionalData, 'additional_data', self.AdditionalDataClass)
        # parse Flow elements:
        self._get_xml_subclass(xml, TAG_Flow, 'flows', self.FlowClass)

    def __str__(self):
        return 'EventData start=%s detect=%s end=%s descriptions: %s' % (
            self.start_time, self.detect_time, self.end_time, ', '.join(self.descriptions))


    def get_sources (self):
        """
        return list of systems with category='source', in all flows
        """
        result = []
        for flow in self.flows:
            result += flow.get_sources()
        return result


    def get_targets (self):
        """
        return list of systems with category='target', in all flows
        """
        result = []
        for flow in self.flows:
            result += flow.get_targets()
        return result


#------------------------------------------------------------------------------
class HistoryItem (_XMLMapper):
    """
    The History class is a log of the significant events or actions
    performed by the involved parties during the course of handling the
    incident.

    The level of detail maintained in this log is left up to the
    discretion of those handling the incident.

    The HistoryItem class is an entry in the History log
    that documents a particular action or event that occurred in the
    course of handling the incident.  The details of the entry are a
    free-form description, but each can be categorized with the type
    attribute.

    attributes:
    - action: enum of str
    - additional_data: AdditionalData
    - datetime: str
    - description: list of str
    - ext_action: str
    - restriction: enum of str
    """

    # class variables for subelement classes:
    # can be overridden when implementing IODEF extensions
    AdditionalDataClass = AdditionalData


    def __init__(self, action=None, additional_data=None,
        datetime=None, descriptions=None, ext_action=None, restriction=None,
        from_xml=None):
        self.action = action
        self.additional_data = []
        if additional_data:
            self.additional_data = additional_data
        self.datetime = datetime
        self.descriptions = []
        if descriptions:
            self.descriptions = descriptions
        self.ext_action = ext_action
        self.restriction = restriction
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        xml = ET.Element(TAG_HistoryItem)
        self._set_xml_attribs(xml, 'action', 'restriction', ext_action='ext-action')
        self._set_xml_tag(xml, TAG_DateTime, 'datetime')
        self._set_xml_taglist(xml, TAG_Description, 'descriptions')
        self._set_xml_subclass(xml, 'additional_data')
        return xml

    def from_xml(self, xml):
        self._get_xml_attribs(xml, 'action', 'restriction', ext_action='ext-action')
        self._get_xml_tag(xml, TAG_DateTime, 'datetime')
        self._get_xml_taglist(xml, TAG_Description, 'descriptions')
        # parse AdditionalData elements:
        self._get_xml_subclass(xml, TAG_AdditionalData, 'additional_data', self.AdditionalDataClass)

    def __str__(self):
        return 'HistoryItem action=%s ext_action=%s datetime=%s descriptions: %s' % (
            self.action, self.ext_action, self.datetime, ', '.join(self.descriptions))


#------------------------------------------------------------------------------
class Impact (_XMLMapper):
    """
    class storing the impact assessment of an incident

    attributes:
    - description: str
    - lang: enum of str
    - severity: enum of str
    - completion: enum of str
    - type: enum of str
    - ext_type: str
    """

    def __init__(self, description=None, lang=None, severity=None,
        completion=None, type=None, ext_type=None,
        from_xml=None):
        self.description = description
        self.lang = lang
        self.severity = severity
        self.completion = completion
        self.type = type
        self.ext_type = ext_type
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        xml = ET.Element(TAG_Impact)
        if self.description:
            xml.text = self.description
        self._set_xml_attribs(xml, 'lang', 'severity',
            'completion', 'type', ext_type='ext-type')
        return xml

    def from_xml(self, xml):
        self._get_xml_attribs(xml, 'lang', 'severity',
            'completion', 'type', ext_type='ext-type')
        self.description = xml.text

    def __str__(self):
        return 'Impact type=%s severity=%s completion=%s description: %s' % (
            self.type, self.severity, self.completion, self.description)


#------------------------------------------------------------------------------
class Assessment (_XMLMapper):
    """
    class storing the assessment of an incident

    attributes:
    - occurence: enum of str
    - restriction: enum of str
    """

    # class variables for subelement classes:
    # can be overridden when implementing IODEF extensions
    ImpactClass = Impact

    def __init__(self, occurence=None, restriction=None, impacts=None,
        from_xml=None):
        self.occurence = occurence
        self.restriction = restriction
        self.impacts = []
        if impacts:
            self.impacts = impacts
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        xml = ET.Element(TAG_Assessment)
        self._set_xml_attribs(xml, 'occurence', 'restriction')
        self._set_xml_subclass(xml, 'impacts')
        return xml

    def from_xml(self, xml):
        self._get_xml_attribs(xml, 'occurence', 'restriction')
        # parse Impact subelements:
        self._get_xml_subclass(xml, TAG_Impact, 'impacts', self.ImpactClass)
##        self.impacts = []
##        for subelem in xml.findall(TAG_Impact):
##            self.impacts.append(self.ImpactClass(from_xml=subelem))

    def __str__(self):
        return 'Assessment occurence=%s restriction=%s' % (self.occurence,
            self.restriction)


#------------------------------------------------------------------------------
class Incident (_XMLMapper):
    """
    Incident class

    attributes:
    - lang: language, such as 'en'
    - purpose: purpose of report, such as 'reporting'
    - id: unique identifier of the report
    - id_name: name of originator of the report, or namespace where id is unique
    """

    # class variables for subelement classes:
    # can be overridden when implementing IODEF extensions
    AssessmentClass = Assessment
    AdditionalDataClass = AdditionalData
    HistoryItemClass = HistoryItem
    EventDataClass = EventData

    def __init__(self, lang='en', purpose='reporting', id=None, id_name=None,
        report_time=None, detect_time=None, start_time=None, end_time=None,
        descriptions=None, restriction=None, ext_purpose=None,
        assessments=None, additional_data=None,
        history=None, history_restriction=None, event_data=None,
        from_xml=None):
        self.lang = lang
        self.purpose = purpose
        self.id = id
        self.id_name = id_name
        self.report_time = report_time
        self.detect_time = detect_time
        self.start_time  = start_time
        self.end_time    = end_time
        self.restriction = restriction
        self.ext_purpose = ext_purpose
        self.history = []
        if history: self.history = history
        self.history_restriction = history_restriction
        self.descriptions = []
        if descriptions: self.descriptions = descriptions
        self.assessments = []
        if assessments: self.assessments = assessments
        self.additional_data = []
        if additional_data: self.additional_data = additional_data
        self.event_data = _new_list(event_data)
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        xml = ET.Element(TAG_Incident)
        self._set_xml_attribs(xml, 'lang', 'purpose', 'restriction',
            ext_purpose='ext-purpose')
        self._set_xml_tag(xml, TAG_IncidentID, 'id', id_name='name')
        self._set_xml_tag(xml, TAG_ReportTime, 'report_time')
        self._set_xml_tag(xml, TAG_DetectTime, 'detect_time')
        self._set_xml_tag(xml, TAG_StartTime, 'start_time')
        self._set_xml_tag(xml, TAG_EndTime, 'end_time')
        self._set_xml_taglist(xml, TAG_Description, 'descriptions')
        # create History and HistoryItem:
        history = self._set_xml_tag(xml, TAG_History, None, history_restriction='restriction')
        self._set_xml_subclass(history, 'history')
        self._set_xml_subclass(xml, 'assessments')
        self._set_xml_subclass(xml, 'additional_data')
        self._set_xml_subclass(xml, 'event_data')
        return xml

    def from_xml(self, xml):
        self._get_xml_attribs(xml, 'lang', 'purpose', 'restriction',
            ext_purpose='ext-purpose')
        self._get_xml_tag(xml, TAG_IncidentID, 'id', id_name='name')
        self._get_xml_tag(xml, TAG_ReportTime, 'report_time')
        self._get_xml_tag(xml, TAG_DetectTime, 'detect_time')
        self._get_xml_tag(xml, TAG_StartTime, 'start_time')
        self._get_xml_tag(xml, TAG_EndTime, 'end_time')
        self._get_xml_taglist(xml, TAG_Description, 'descriptions')
        # parse History and HistoryItem:
        history = self._get_xml_tag(xml, TAG_History, None, history_restriction='restriction')
        self.history = []
        if history is not None:
            self._get_xml_subclass(history, TAG_HistoryItem, 'history', self.HistoryItemClass)
        # parse Assessment elements:
        self._get_xml_subclass(xml, TAG_Assessment, 'assessments', self.AssessmentClass)
        # parse AdditionalData elements:
        self._get_xml_subclass(xml, TAG_AdditionalData, 'additional_data', self.AdditionalDataClass)
        # parse EventData elements:
        self._get_xml_subclass(xml, TAG_EventData, 'event_data', self.EventDataClass)

    def __str__(self):
        return 'Incident ID=%s id_name=%s lang=%s purpose=%s' % (
            self.id, self.id_name, self.lang, self.purpose)

    def get_first_impact(self):
        """
        helper method to get the first Impact object from the Assessment objects
        """
        for assessment in self.assessments:
            if assessment.impacts:
                return assessment.impacts[0]
        return None


    def add_impact(self, description=None, lang=None, severity=None,
        completion=None, type=None, ext_type=None, occurence=None, restriction=None):
        """
        helper method to add a new Assessment and Impact object
        (does not check if existing Assessment/Impact objects are present)
        """
        # create new Impact object:
        impact = self.AssessmentClass.ImpactClass(description=description, lang=lang,
            severity=severity, completion=completion, type=type, ext_type=ext_type)
        # create new Assessment object:
        assessment = self.AssessmentClass(occurence=occurence, restriction=restriction,
            impacts=[impact])
        self.assessments.append(assessment)


    def get_sources (self):
        """
        return list of systems with category='source', in all event_data/flows
        """
        result = []
        for ev in self.event_data:
            result += ev.get_sources()
        return result


    def get_targets (self):
        """
        return list of systems with category='target', in all event_data/flows
        """
        result = []
        for ev in self.event_data:
            result += ev.get_targets()
        return result


    def add_system (self, category='source', name=None, address=None,
        location=None, description=None, event_data=None, flow=None):
        """
        Add a System object to the incident, such as a source or a target of the
        incident.
        If event_data or flow is provided, the corresponding object is used as
        parent, else the first EventData or Flow object is used, or created if
        not present.

        - category: str, 'source' or 'target'
        - name: str, hostname
        - address: str (IP address) or list of str
        - location: str
        - description: str
        - event_data: EventData or None
        - flow: Flow or None
        """
        if event_data is None and flow is None:
            # take 1st eventdata or create one:
            if len(self.event_data)>0:
                event_data = self.event_data[0]
            else:
                event_data = self.EventDataClass()
                self.event_data.append(event_data)
        if flow is None:
            # take 1st flow or create one:
            if len(event_data.flows)>0:
                flow = event_data.flows[0]
            else:
                flow = event_data.FlowClass()
                event_data.flows.append(flow)
        # create system object
        SystemClass = self.EventDataClass.FlowClass.SystemClass
        system = SystemClass(
            category=category, descriptions=_make_list(description),
            node_names=_make_list(name), node_location=location)
        system.node_addresses = [SystemClass.AddressClass(address=address)]
        # add it to flow:
        flow.systems.append(system)
        return system

#------------------------------------------------------------------------------
class IODEF_Document (_XMLMapper):
    """
    IODEF Document class

    attributes:
    - lang: language, such as 'en'
    - version: version, such as '1.00'
    """

    # class variables for subelement classes:
    # can be overridden when implementing IODEF extensions
    IncidentClass = Incident

    def __init__(self, lang='en', version='1.00', incidents=None, from_xml=None):
        self.lang = lang
        self.version = version
        self.incidents = []
        if incidents is not None:
            self.incidents = incidents
        if from_xml is not None:
            self.from_xml(from_xml)

    def to_xml(self):
        # start with an empty IODEF document:
        xml = ET.fromstring(EMPTY_IODEF)
        # set main attributes:
        self._set_xml_attribs(xml, 'lang', 'version')
        # add each incident report
        self._set_xml_subclass(xml, 'incidents')
        return xml

    def to_xml_str(self, pretty_print=False):
        xml = self.to_xml()
        if LXML:
            return ET.tostring(xml, pretty_print=pretty_print)
        else:
            return ET.tostring(xml)

    def __str__(self):
        return self.to_xml_str(pretty_print=True)

    def from_xml(self, xml_str):
        # parse string to XML element:
        xml = ET.fromstring(xml_str)
        # get main attributes:
        self._get_xml_attribs(xml, 'lang', 'version')
        # parse incidents:
        self._get_xml_subclass(xml, TAG_Incident, 'incidents', self.IncidentClass)


def parse (xml_string):
    """
    Parse an XML string containing an IODEF incident report
    return an IODEF_Document object
    """
    return IODEF_Document(from_xml = xml_string)


def parse_file (filename):
    """
    Parse an XML file containing an IODEF incident report
    return an IODEF_Document object
    """
    return parse(open(filename).read())


#=== MAIN =====================================================================

if __name__ == '__main__':

    def dump_sources_targets(incident):
        print 'Sources:'
        for system in incident.get_sources():
            print '- node name(s): %s - address(es): %s - location: %s' %(
                ','.join(system.node_names),
                ','.join(system.get_addresses()),
                system.node_location)
        print 'Targets:'
        for system in incident.get_targets():
            print '- node name(s): %s - address(es): %s - location: %s' %(
                ','.join(system.node_names),
                ','.join(system.get_addresses()),
                system.node_location)
        print ''


    print 'Create an IODEF report:'
    iodef1 = IODEF_Document()
##    impact = Impact(description='DoS on system XYZ', type='dos',
##        severity='medium', completion='succeeded')
##    assessment = Assessment(occurence='actual', restriction='need-to-know',
##        impacts=[impact])
    incident1 = Incident(id='1234', id_name='CSIRT-X',
        report_time='2001-09-13T15:05:00+00:00',
        detect_time='2001-09-13T10:20:00+00:00',
        start_time='2001-09-13T10:19:24+00:00',
        end_time='2001-09-13T13:47:12+00:00',
        ext_purpose='TEST',
##        assessments=[assessment],
        )
    incident1.add_system(category='source', address='192.168.1.2')
    incident1.add_system(category='target', address='192.168.3.7', name='XYZ')
    incident1.add_impact(description='DoS on system XYZ', type='dos',
        severity='medium', completion='succeeded', occurence='actual',
        restriction='need-to-know')
    adata = AdditionalData(data='Unclassified', dtype='string',
        meaning='Security classification', formatid='classification')
    incident1.additional_data = [adata]
    print incident1
##    print assessment
    print incident1.assessments[0]
##    print impact
    print incident1.assessments[0].impacts[0]
    print 'First impact type:', incident1.get_first_impact().type
    print 'Additional data [0]:', incident1.additional_data[0]
    dump_sources_targets(incident1)
    iodef1.incidents.append(incident1)
    print iodef1

    import glob
    for filename in glob.glob('examples/IODEF_sample*.xml', ):
        print '\nParse an IODEF report from file "%s":' % filename
        xml = open(filename).read()
        iodef2 = IODEF_Document(from_xml = xml)
        print 'incidents:'
        for incident in iodef2.incidents:
            print incident
            for h in incident.history:
                print '-', h
            for event_data in incident.event_data:
                print '-', event_data
                for flow in event_data.flows:
                    print '  -', flow
                    for s in flow.systems:
                        print '    -', s
                        for address in s.node_addresses:
                            print '      -', address
            dump_sources_targets(incident)
        print 'serialize back to XML:'
        print iodef2

