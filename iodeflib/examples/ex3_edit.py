import sys
sys.path.append('..')

import iodeflib
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

