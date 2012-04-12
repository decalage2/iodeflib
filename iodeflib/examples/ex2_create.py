import sys
sys.path.append('..')

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
