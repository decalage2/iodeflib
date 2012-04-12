iodeflib
========

iodeflib is a python library to create, parse and edit cyber incident
reports using the IODEF XML format (`RFC
5070 <http://www.ietf.org/rfc/rfc5070.txt>`_).

Project website: http://www.decalage.info/python/iodeflib

On the one hand, IODEF is a very rich, flexible and extensible XML
format to describe cyber incidents. On the other hand, it can be quite
complex to use in practice, because it is difficult to parse IODEF
content due to its rich features and deeply nested structure.

iodeflib is an attempt to provide a simple API to ease the development
of IODEF-aware scripts and applications.

iodeflib is different from the
`iodef <http://pypi.python.org/pypi/iodef>`_ python package published on
PyPI and Sourceforge. In fact I created iodeflib because I was quite
disappointed by the complexity of the iodef package. iodef was generated
automatically from the IODEF XML schema using
`GenerateDS <http://www.rexx.com/~dkuhlman/generateDS.html>`_, which
indeed exposes the complexity of the IODEF schema.

In contrast, iodeflib was carefully designed in order to keep the python
interface as simple as possible, hiding some unnecessarily nested
structures of the IODEF schema, and adding more convenient shortcuts.
Iodeflib is also designed to be extensible.

Download
--------

Go to https://bitbucket.org/decalage/iodeflib/downloads

Usage
-----

The following sample scripts are provided in the iodeflib package, in
the examples subfolder.

How to parse IODEF data
~~~~~~~~~~~~~~~~~~~~~~~

::

        import iodeflib
        # open XML file and parse IODEF:
        iodef = iodeflib.parse_file('iodef.xml')
        # print some attributes for each incident:
        for incident in iodef.incidents:
            print 'Incident %s from %s - impact type: %s' % (incident.id,
                incident.id_name, incident.get_first_impact().type)
            for desc in incident.descriptions:
                print desc
            print 'Sources:'
            for system in incident.get_sources(): print system.get_addresses()
            print 'Targets:'
            for system in incident.get_targets(): print system.get_addresses()
            print ''

How to create IODEF data
~~~~~~~~~~~~~~~~~~~~~~~~

::

        import iodeflib
        # create a new IODEF document:
        iodef = iodeflib.IODEF_Document()
        # create a new incident:
        incident1 = iodeflib.Incident(id='1234', id_name='CSIRT-X',
            report_time='2011-09-13T11:01:00+00:00',
            start_time='2011-09-13T10:19:24+00:00')
        # add description:
        incident1.descriptions = ['Detected denial of service attack']
        # add sources and targets:
        incident1.add_system(category='source', address='192.168.1.2')
        incident1.add_system(category='target', address='192.168.3.7', name='XYZ')
        # add impact assessment:
        incident1.add_impact(description='DoS on system XYZ', type='dos',
            severity='medium', completion='succeeded', occurence='actual',
            restriction='need-to-know')
        iodef.incidents.append(incident1)
        # serialize IODEF to XML, print it and save it to a file:
        print iodef
        open('iodef2.xml', 'w').write(str(iodef))

How to edit IODEF data
~~~~~~~~~~~~~~~~~~~~~~

::

        # open XML file and parse IODEF:
        iodef = iodeflib.parse_file('iodef2.xml')
        # get incident, add end time and history item:
        incident1 = iodef.incidents[0]
        histitem = iodeflib.HistoryItem(descriptions=['Blocked source IP.'],
            datetime='2011-09-13T13:47:12+00:00')
        incident1.history.append(histitem)
        incident1.end_time='2011-09-13T13:47:12+00:00'
        incident1.report_time='2011-09-13T13:52:00+00:00'
        # save IODEF back to an XML file:
        print iodef
        open('iodef2_updated.xml', 'w').write(str(iodef))

More info on the API
~~~~~~~~~~~~~~~~~~~~

See iodeflib.html in the iodeflib folder, or check the docstrings in the
source code.

Status
------

Not all the features of RFC 5070 are implemented in iodeflib yet.
However, the most useful classes are already available.

How to contribute
-----------------

Either send an e-mail to the author, or use the fork / pull request
features of Bitbucket to propose improvements to the code.

See the TODO section in the source code for a list of potential
improvements.

How to report bugs
------------------

You may create an issue ticket on
https://bitbucket.org/decalage/iodeflib/issues, or send an e-mail to the
author.

Please provide enough information to reproduce the bug: which version
you use, which operating system and version of Python, etc. Please also
provide sample code and data files to reproduce the bug.

License
-------

Copyright (c) 2011-2012, Philippe Lagadec (http://www.decalage.info).
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

-  Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
-  Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
