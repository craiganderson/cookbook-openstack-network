#!/usr/bin/env python

### Import statements ###
import pdb
import sys
import argparse
import uuid
import os


### Input Args ###
parser = argparse.ArgumentParser(description='get credentials and other inputs')
parser.add_argument('-A', '--OS_AUTH_URL', action="store", dest="auth_url", help='keystone auth url')
parser.add_argument('-T', '--OS_TENANT_NAME', action="store", dest="admin_project", help='project name where the authenticating user has the admin role.  This script will NOT work if this use does not have the admin role for this project.')
parser.add_argument('-U', '--OS_USERNAME', action="store", dest="admin_username", help='username to authenticate with to perform the administrator level actions required by this script.')
parser.add_argument('-P', '--OS_PASSWORD', action="store", dest="admin_password", help='password for the user specified by OS_USERNAME.')
parser.add_argument('-R', '--OS_REGION_NAME', action="store", dest="region", help='region specified by OS_REGION_NAME.')
parser.add_argument('-Z', '--CONEXUS_TENANT_ID', action="store", dest="conexus_tenant_id", help='tenant ID for which new conexus resources should be created')
args = vars(parser.parse_args())

conexus_tenant_id = args['conexus_tenant_id']

auth_url = args['auth_url']
if auth_url == None:
  auth_url = os.environ.get('OS_AUTH_URL')
  if auth_url == None:
    print 'Error: you need to supply the --OS_AUTH_URL argument to this script, or define this environment variable'
    sys.exit(1)

admin_project = args['admin_project']
if admin_project == None:
  admin_project = os.environ.get('OS_TENANT_NAME')
  if admin_project == None:
    print 'Error: You need to supply the --OS_TENANT_NAME argument to this script, or define this environment variable'
    sys.exit(1)

admin_username = args['admin_username']
if admin_username == None:
  admin_username = os.environ.get('OS_USERNAME')
  if admin_username == None:
    print 'Error: You need to supply the --OS_USERNAME argument to this script, or define this environment variable'
    sys.exit(1)

admin_password = args['admin_password']
if admin_password == None:
  admin_password = os.environ.get('OS_PASSWORD')
  if admin_password == None:
    print 'Error: You need to supply the --OS_PASSWORD argument to this script, or define this environment variable'
    sys.exit(1)

region = args['region']
if region == None:
  region = os.environ.get('OS_REGION_NAME')
  if region == None:
    print 'Error: You need to supply the --OS_REGION_NAME argument to this script, or define this environment variable'
    sys.exit(1)


class conexus:
  def __init__(self, vlan, transit_net_base, transit_net_mask, tenant_net_base, tenant_net_mask):
    self.vlan = vlan
    self.transit_net_base = transit_net_base
    self.transit_net_mask = transit_net_mask
    self.transit_net_cidr = transit_net_base + '/' + transit_net_mask
    self.tenant_net_base = tenant_net_base
    self.tenant_net_mask = tenant_net_mask
    self.tenant_net_cidr = tenant_net_base + '/' + tenant_net_mask

class conexus_ownership:
  def __init__(self, tenant_id, segmentation_id=None, transit_subnet=None, tenant_subnet=None, transit_net_id=None, transit_subnet_id=None, tenant_subnet_id=None, tenant_net_id=None):
    self.tenant_id = tenant_id
    self.segmentation_id = segmentation_id
    self.transit_subnet = transit_subnet
    self.tenant_subnet = tenant_subnet
    self.transit_net_id = transit_net_id
    self.transit_subnet_id = transit_subnet_id
    self.tenant_subnet_id = tenant_subnet_id
    self.tenant_net_id = tenant_net_id

conexus_ownership_list = []
conexus_list = []
if region == 'ccptest-region1':
  conexus_list.append(conexus(401, '135.16.55.0', '29', '135.21.86.0', '28'))
  conexus_list.append(conexus(402, '135.16.55.8', '29', '135.21.86.16', '28'))
  conexus_list.append(conexus(403, '135.16.55.16', '29', '135.21.86.32', '28'))
  conexus_list.append(conexus(404, '135.16.55.24', '29', '135.21.86.48', '28'))
  conexus_list.append(conexus(405, '135.16.55.32', '29', '135.21.86.64', '28'))
  conexus_list.append(conexus(406, '135.16.55.40', '29', '135.21.86.80', '28'))
  conexus_list.append(conexus(407, '135.16.55.48', '29', '135.21.86.96', '28'))
  conexus_list.append(conexus(408, '135.16.55.56', '29', '135.21.86.112', '28'))
  conexus_list.append(conexus(409, '135.16.55.64', '29', '135.21.86.128', '28'))
  conexus_list.append(conexus(410, '135.16.55.72', '29', '135.21.86.144', '28'))
  conexus_list.append(conexus(411, '135.16.55.80', '29', '135.21.86.160', '28'))
  conexus_list.append(conexus(412, '135.16.55.88', '29', '135.21.86.176', '28'))
  conexus_list.append(conexus(413, '135.16.55.96', '29', '135.21.86.192', '28'))
  conexus_list.append(conexus(414, '135.16.55.104', '29', '135.21.86.208', '28'))
  conexus_list.append(conexus(415, '135.16.55.112', '29', '135.21.86.224', '28'))
  conexus_list.append(conexus(416, '135.16.55.120', '29', '135.21.86.240', '28'))
  conexus_list.append(conexus(417, '135.16.55.128', '29', '135.25.94.128', '28'))
  conexus_list.append(conexus(418, '135.16.55.136', '29', '135.25.94.144', '28'))
  conexus_list.append(conexus(419, '135.16.55.144', '29', '135.25.94.160', '28'))
  conexus_list.append(conexus(420, '135.16.55.152', '29', '135.25.94.176', '28'))
  conexus_list.append(conexus(421, '135.16.55.160', '29', '135.25.94.192', '28'))
  conexus_list.append(conexus(422, '135.16.55.168', '29', '135.25.94.208', '28'))
  conexus_list.append(conexus(423, '135.16.55.176', '29', '135.25.94.224', '28'))
  conexus_list.append(conexus(424, '135.16.55.184', '29', '135.25.94.240', '28'))
elif region == 'ccpdev-region1':
  conexus_list.append(conexus(401, '135.21.158.0', '29', '135.21.158.80', '28'))
  conexus_list.append(conexus(402, '135.21.158.8', '29', '135.21.158.96', '28'))
  conexus_list.append(conexus(403, '135.21.158.16', '29', '135.21.158.112', '28'))
  conexus_list.append(conexus(404, '135.21.158.24', '29', '135.21.158.128', '28'))
  conexus_list.append(conexus(405, '135.21.158.32', '29', '135.21.158.144', '28'))
  conexus_list.append(conexus(406, '135.21.158.40', '29', '135.21.158.160', '28'))
  conexus_list.append(conexus(407, '135.21.158.48', '29', '135.21.158.176', '28'))
  conexus_list.append(conexus(408, '135.21.158.56', '29', '135.21.158.192', '28'))
  conexus_list.append(conexus(409, '135.21.158.64', '29', '135.21.158.208', '28'))
  conexus_list.append(conexus(410, '135.21.158.72', '29', '135.21.158.224', '28'))

# Create network
from neutronclient.v2_0 import client
neutron = client.Client(username=admin_username, password=admin_password, tenant_name=admin_project, auth_url=auth_url)

list_of_networks = neutron.list_networks()
net_list = list_of_networks['networks']

list_of_subnets = neutron.list_subnets()
subnet_list = list_of_subnets['subnets']

for net in net_list:
  for conexus in conexus_list:
    if net.get('provider:physical_network') == 'conexus' and net.get('provider:network_type') == 'vlan' and net.get('provider:segmentation_id') == conexus.vlan:
      for conexus_ownership_obj in conexus_ownership_list:
        if conexus_ownership_obj.tenant_id == net.get('tenant_id'):
          conexus_ownership_obj.segmentation_id = net.get('provider:segmentation_id')
          conexus_ownership_obj.transit_net_id = net.get('id')
          break
      else:
        conexus_ownership_list.append(conexus_ownership(net.get('tenant_id'), segmentation_id=conexus.vlan, transit_net_id=net.get('id')))

for subnet in subnet_list:
  for conexus in conexus_list:
    if subnet.get('cidr') == conexus.transit_net_cidr:
      for conexus_ownership_obj in conexus_ownership_list:
        if conexus_ownership_obj.tenant_id == subnet.get('tenant_id'):
          conexus_ownership_obj.transit_subnet = conexus.transit_net_cidr
          conexus_ownership_obj.transit_subnet_id = subnet.get('id')
          break
      else:
        conexus_ownership_list.append(conexus_ownership(subnet.get('tenant_id'), transit_subnet=conexus.transit_net_cidr, transit_subnet_id=subnet.get('id')))
    elif subnet.get('cidr') == conexus.tenant_net_cidr:
      for conexus_ownership_obj in conexus_ownership_list:
        if conexus_ownership_obj.tenant_id == subnet.get('tenant_id'):
          conexus_ownership_obj.tenant_subnet = conexus.tenant_net_cidr
          conexus_ownership_obj.tenant_subnet_id = subnet.get('id')
          conexus_ownership_obj.tenant_net_id = subnet.get('network_id')
          break
      else:
        conexus_ownership_list.append(conexus_ownership(subnet.get('tenant_id'), tenant_subnet=conexus.tenant_net_cidr, tenant_subnet_id=subnet.get('id'), tenant_net_id=subnet.get('network_id')))

headers_list = ['tenant_id', 'vlan', 'transit_net', 'tenant_net']
end_count=0
row_list = []
data = []
for conexus_ownership_obj in conexus_ownership_list:
  row_list = [conexus_ownership_obj.tenant_id] + row_list
  current_row = [conexus_ownership_obj.segmentation_id, conexus_ownership_obj.transit_subnet, conexus_ownership_obj.tenant_subnet]
  data = [current_row] + data
  #print conexus_ownership_obj.tenant_id, conexus_ownership_obj.segmentation_id, conexus_ownership_obj.transit_subnet, conexus_ownership_obj.tenant_subnet

print '\nThe following allocation of conexus networks to tenants is:\n'
#row_format = "{:>32}" * (len(headers_list) + 1)
row_format = "{:>32}" * (len(headers_list))
#term_width = (len(headers_list) + 1) * 32
term_width = (len(headers_list)) * 32
#print row_format.format("", *headers_list)
print row_format.format(*headers_list)
count = 0
for col, row in zip(row_list, data):
  if count == end_count:
    print '-' * term_width
  print row_format.format(col, *row)
  count += 1

for indx, conexus in enumerate(conexus_list):
  for conexus_ownership_obj in conexus_ownership_list:
    if conexus.vlan == conexus_ownership_obj.segmentation_id:
      conexus_list[indx] = []

headers_list = ['vlan', 'transit_net', 'tenant_net']
end_count=0
row_list = []
data = []
available_conexus = False
for conexus in conexus_list:
  try:
    row_list += [conexus.vlan]
    current_row = [conexus.transit_net_cidr, conexus.tenant_net_cidr]
    data = [current_row] + data
    if not available_conexus:
      available_conexus = conexus
  except AttributeError:
    continue

print '\n\nThe segments available for conexus allocation are:\n'
row_format = "{:>20}" * (len(headers_list))
term_width = (len(headers_list)) * 20
print row_format.format(*headers_list)
count = 0
for col, row in zip(row_list, data):
  if count == end_count:
    print '-' * term_width
  print row_format.format(col, *row)
  count += 1

# Setup new conexus resources for specified tenant id
if conexus_tenant_id:
  print '\n'
  if not available_conexus:
    print 'Sorry!  No more conexus networks are available for allocation.'
    sys.exit(1)

  from keystoneclient.v2_0 import *
  keystone = client.Client(username=admin_username, password=admin_password, tenant_name=admin_project, auth_url=auth_url)
  # Query list of existing tenants
  current_tenant_list = keystone.tenants.list()
  for tenant in current_tenant_list:
    if conexus_tenant_id in tenant.id:
      print '[OK] Found tenant with ID: ' + str(conexus_tenant_id)
      break
  else:
    print '[ERROR] Could not find tenant with ID: ' + str(conexus_tenant_id)
    print '[ERROR] Make sure tenant ID is correct and that you are using administrative credentials'
    sys.exit(1)

  transit_net_id = None
  transit_subnet_id = None
  tenant_subnet_id = None
  tenant_net_id = None
  for conexus_ownership_obj in conexus_ownership_list:
    if conexus_ownership_obj.tenant_id == conexus_tenant_id:
      transit_net_id = conexus_ownership_obj.transit_net_id
      transit_subnet_id = conexus_ownership_obj.transit_subnet_id
      tenant_subnet_id = conexus_ownership_obj.tenant_subnet_id
      tenant_net_id = conexus_ownership_obj.tenant_net_id
      break

  if transit_net_id:
    for net in net_list:
      if net.get('id') == transit_net_id:
        if net.get('shared') == False:
          print '[OK] Shared flag = False for transit network'
        else:
          print '[ERROR] Share flag is not False for transit network'
        if net.get('router:external') == True:
          print '[OK] router:external flag = True for transit network'
        else:
          print '[ERROR] router:external flag is not True for transit network'
        break
  else:
    transit_net_name = 'conexus_transit_' + str(available_conexus.vlan) + '_net'
    transit_net = neutron.create_network(body={"network" : {"name": transit_net_name, "admin_state_up": "true", "router:external": "true", "tenant_id": conexus_tenant_id, "provider:network_type": "vlan", "provider:physical_network": "conexus", "provider:segmentation_id": available_conexus.vlan}})
    transit_net_id = transit_net['network']['id']

  if transit_subnet_id:
    subnet_allocation_start = '.'.join(conexus_ownership_obj.transit_subnet.split('/')[0].split('.')[:-1] + [str(int(conexus_ownership_obj.transit_subnet.split('/')[0].split('.')[-1]) + 6)])
    subnet_allocation_end = '.'.join(conexus_ownership_obj.transit_subnet.split('/')[0].split('.')[:-1] + [str(int(conexus_ownership_obj.transit_subnet.split('/')[0].split('.')[-1]) + 6)])
    for subnet in subnet_list:
      if subnet.get('id') == transit_subnet_id:
        if subnet.get('enable_dhcp') == False:
          print '[OK] DHCP disabled for transit subnet'
        else:
          print '[ERROR] DHCP is enabled for transit subnet'
        if subnet.get('network_id') == transit_net_id:
          print '[OK] transit subnet belongs to correct transit network'
        else:
          print '[ERROR] transit subnet belongs to wrong transit network'
        if subnet.get('allocation_pools')[0].get('start') == subnet_allocation_start:
          print '[OK] transit subnet allocation pool start matches expected value'
        else:
          print '[ERROR] transit subnet allocation pool start value: ' + subnet.get('allocation_pools')[0].get('start') + ' does not match expected start value: ' + subnet_allocation_start
        if subnet.get('allocation_pools')[0].get('end') == subnet_allocation_end:
          print '[OK] transit subnet allocation pool end matches expected value'
        else:
          print '[ERROR] transit subnet allocation pool end value: ' + subnet.get('allocation_pools')[0].get('end') + ' does not match expected end value: ' + subnet_allocation_end
        break
  else:
    subnet_allocation_start = '.'.join(available_conexus.transit_net_base.split('.')[:-1] + [str(int(available_conexus.transit_net_base.split('.')[-1]) + 6)])
    subnet_allocation_end = '.'.join(available_conexus.transit_net_base.split('.')[:-1] + [str(int(available_conexus.transit_net_base.split('.')[-1]) + 6)])
    transit_subnet_name = 'conexus_transit_' + str(available_conexus.vlan) + '_subnet'
    transit_subnet = neutron.create_subnet(body={"subnet" : {"name":transit_subnet_name,"network_id":transit_net_id,"tenant_id": conexus_tenant_id,"ip_version":4,"cidr":available_conexus.transit_net_cidr,'enable_dhcp':False,"allocation_pools":[{"start":subnet_allocation_start,"end":subnet_allocation_end}]}})
    transit_subnet_id = transit_subnet['subnet']['id']

  if tenant_net_id:
    for net in net_list:
      if net.get('id') == tenant_net_id:
        if net.get('provider:network_type') == 'gre':
          print '[OK] tenant network type is gre'
        else:
          print '[ERROR] tenant network value: ' + net.get('provider:network_type') + ' does not match expected value: gre'
        if net.get('shared') == False:
          print '[OK] Shared flag = False for tenant network'
        else:
          print '[ERROR] Share flag is not False for tenant network'
        if net.get('router:external') == False:
          print '[OK] router:external flag = False for tenant network'
        else:
          print '[ERROR] router:external flag is not False for tenant network'
        break
  else:
    tenant_net_name = 'conexus_tenant_' + str(available_conexus.vlan) + '_net'
    tenant_net = neutron.create_network(body={"network" : {"name": tenant_net_name, "admin_state_up": "true", "tenant_id": conexus_tenant_id}})
    tenant_net_id = tenant_net['network']['id']

  if tenant_subnet_id:
    for subnet in subnet_list:
      if subnet.get('id') == tenant_subnet_id:
        if subnet.get('enable_dhcp') == True:
          print '[OK] DHCP enabled for tenant subnet'
        else:
          print '[ERROR] DHCP is disabled for tenant subnet'
        if subnet.get('network_id') == tenant_net_id:
          print '[OK] tenant subnet belongs to correct tenant network'
        else:
          print '[ERROR] tenant subnet belongs to wrong tenant network'
        gateway_ip = subnet.get('gateway_ip')
        break
  else:
    tenant_subnet_name = 'conexus_tenant_' + str(available_conexus.vlan) + '_subnet'
    tenant_subnet = neutron.create_subnet(body={"subnet" : {"name":tenant_subnet_name,"network_id":tenant_net_id,"tenant_id": conexus_tenant_id,"ip_version":4,"cidr":available_conexus.tenant_net_cidr}})
    tenant_subnet_id = tenant_subnet['subnet']['id']
    gateway_ip = tenant_subnet['subnet']['gateway_ip']

  # if router exists with attached interface for tenant net, get/use id of that router
  list_of_ports = neutron.list_ports()
  port_list = list_of_ports['ports']
  matching_internal_port_found = False
  for port in port_list:
    for fixed_ip in port['fixed_ips']:
      if fixed_ip['subnet_id'] == tenant_subnet_id and fixed_ip['ip_address'] == gateway_ip:
        port_details = neutron.show_port(port['id'])['port']
        router_id = port_details['device_id']
        matching_internal_port_found = True
        break

  if not matching_internal_port_found:
    # Create router
    router_name = 'conexus_' + str(available_conexus.vlan) + '_router'
    router = neutron.create_router(body={"router" : {"name": router_name,"tenant_id": conexus_tenant_id}})
    router_id = router['router']['id']

    # Add tenant private network interface to router
    neutron.add_interface_router(router=router_id, body={"subnet_id": tenant_subnet_id})
    print 'Internal router port established.'

  router_details = neutron.show_router(router_id)['router']
  external_gateway_info = router_details.get('external_gateway_info')
  if external_gateway_info:
    router_ext_net_id = external_gateway_info.get('network_id')
    if router_ext_net_id == transit_net_id:
      print '[OK] Tenant router is connected to correct external network'
    else:
      print '[ERROR] Tenant router external network id: ' + router_ext_net_id + ' does not match expected value: ' + transit_net_id
    snat = external_gateway_info.get('enable_snat')
    if snat == False:
      print '[OK] Tenant router is configred with snat disabled'
    else:
      print '[ERROR] Tenant router is not configured for snat disabled'
  else:
    # Set router gateway to transit network
    neutron.add_gateway_router(router=router_id, body={"network_id": transit_net_id,"enable_snat": False})

