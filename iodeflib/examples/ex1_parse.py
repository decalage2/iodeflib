import sys
sys.path.append('..')

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
