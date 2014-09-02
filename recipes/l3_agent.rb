# Encoding: utf-8
#
# Cookbook Name:: openstack-network
# Recipe:: l3_agent
#
# Copyright 2013, AT&T
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

['quantum', 'neutron'].include?(node['openstack']['compute']['network']['service_type']) || return

include_recipe 'openstack-network::common'

platform_options = node['openstack']['network']['platform']
driver_name = node['openstack']['network']['interface_driver'].split('.').last.downcase
main_plugin = node['openstack']['network']['interface_driver_map'][driver_name]

platform_options['neutron_l3_packages'].each do |pkg|
  package pkg do
    options platform_options['package_overrides']
    action :install
    # The providers below do not use the generic L3 agent...
    not_if { ['nicira', 'plumgrid', 'bigswitch'].include?(main_plugin) }
  end
end

service 'neutron-l3-agent' do
  service_name platform_options['neutron_l3_agent_service']
  supports status: true, restart: true

  action :enable
end

template '/etc/neutron/l3_agent.ini' do
  source 'l3_agent.ini.erb'
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  mode   00644
  notifies :restart, 'service[neutron-l3-agent]', :immediately
end

log "main_plugin" do
 message "#{main_plugin}"
end
unless %w(nicira plumgrid bigswitch linuxbridge).include?(main_plugin)

  if node['openstack']['network']['l3']['external_network_bridge'].nil? or node['openstack']['network']['l3']['external_network_bridge'].empty?
    parent_bridge = "br-#{node['openstack']['network']['l3']['external_network_bridge_interface']}"
  else
    parent_bridge = node['openstack']['network']['l3']['external_network_bridge']
  end
  ext_bridge = parent_bridge

  # See http://docs.openstack.org/trunk/openstack-network/admin/content/install_neutron-l3.html
  ext_bridge_iface = node['openstack']['network']['l3']['external_network_bridge_interface']
  execute 'create external network bridge' do
    command "ovs-vsctl add-br #{ext_bridge}"
    action :run
    not_if "ovs-vsctl br-exists #{ext_bridge}"
    only_if "ip link show #{ext_bridge_iface}"
  end
  # If bridge doesn't exist command br-get-external-id returns non-zero.
  # Set up bridge-id on external bridge if bridge exists and doesn't have it
  ext_id = `/usr/bin/ovs-vsctl br-get-external-id #{ext_bridge} bridge-id`
  # If external bridge exists and it hasn't bridge-id - assign it
  if $?.to_i == 0 && ext_id.empty?
    execute 'set bridge-id on external network bridge' do
      command "ovs-vsctl br-set-external-id #{ext_bridge} bridge-id #{ext_bridge}"
      action :run
      notifies :restart, 'service[neutron-server]', :immediately
    end
  end
  check_port = `/usr/bin/ovs-vsctl port-to-br #{ext_bridge_iface}`.delete("\n")
  # If ovs-vsctl port-to-br command returned 0, then <ext_bridge_iface> exists
  if $?.to_i == 0
    # Raise exception and terminate chef execution if ext_bridge_iface is plugged into another bridge on OVS
    if check_port != "#{ext_bridge}"
       Chef::Application.fatal!("Didn't expect the #{ext_bridge_iface} in other bridge #{check_port}! Should be assigned to #{ext_bridge} by chef. Remove this port from invalid bridge (ovs-vsctl del-port #{check_port} #{ext_bridge_iface}) and try again!", 42)
    end
  # If port <ext_bridge_iface> doesn't exist and corresponding interface is present - add it to <ext_bridge>
  else
    execute 'add interface to external network bridge' do
      command "ovs-vsctl add-port #{ext_bridge} #{ext_bridge_iface}"
      action :run
      only_if "ip link show #{ext_bridge_iface}"
    end
  end
end

# New ML2 driven OVS configuration
if node['openstack']['network']['l3']['external_network_bridge'].nil? or node['openstack']['network']['l3']['external_network_bridge'].empty? and not node["openstack"]["network"]["ml2"]["bridge_mappings"].empty?

  # set id for br-int
  # If bridge doesn't exist command br-get-external-id returns non-zero.
  # Set up bridge-id on external bridge if bridge exists and doesn't have it
  ext_id = `/usr/bin/ovs-vsctl br-get-external-id br-int bridge-id`
  # If external bridge exists and it hasn't bridge-id - assign it
  if $?.to_i == 0 && ext_id.empty?
    execute 'set bridge-id on external network bridge' do
      command "ovs-vsctl br-set-external-id br-int bridge-id br-int"
      action :run
      notifies :restart, 'service[neutron-server]', :immediately
    end
  end

  # loop through each of the bridges defined in bridge_mappings
  node["openstack"]["network"]["ml2"]["bridge_mappings"].split(',').each do |bridge_map|
    bridge = bridge_map.split(':')
    ext_bridge = bridge[1]
    patch_iface = "patch-#{bridge[1].split('-')[1]}"
    #ext_bridge_iface = "phy-#{bridge[1]}"

    # Create the current bridge in the bridge mapping (e.g., br-conexus)
    execute "create #{ext_bridge} network bridge" do
      command "ovs-vsctl add-br #{ext_bridge}"
      action :run
      not_if "ovs-vsctl br-exists #{ext_bridge}"
    end

    # Add the peer patch to the parent bridge
    ext_bridge_iface = "patch-bond1-#{bridge[1].split('-')[1]}"
    check_port = `/usr/bin/ovs-vsctl port-to-br #{ext_bridge_iface}`.delete("\n")
    # If ovs-vsctl port-to-br command returned 0, then <ext_bridge_iface> exists
    if $?.to_i == 0
      # Raise exception and terminate chef execution if ext_bridge_iface is plugged into another bridge on OVS
      if check_port != "#{ext_bridge}"
         Chef::Application.fatal!("Didn't expect the #{ext_bridge_iface} in other bridge #{check_port}! Should be assigned to #{ext_bridge} by chef. Remove this port from invalid bridge (ovs-vsctl del-port #{check_port} #{ext_bridge_iface}) and try again!", 42)
      end
    # If port <ext_bridge_iface> doesn't exist and corresponding interface is present - add it to <ext_bridge>
    else
      execute 'add interface to external network bridge' do
        command "ovs-vsctl add-port #{ext_bridge} #{ext_bridge_iface} -- add-port #{parent_bridge} #{patch_iface} -- set interface #{ext_bridge_iface} type=patch options:peer=#{patch_iface} -- set interface #{patch_iface} type=patch options:peer=#{ext_bridge_iface}"
        action :run
        notifies :restart, 'service[neutron-plugin-openvswitch-agent]', :delayed
      end
    end

    #check for patch-bond1-conexus - ex:
    #root@o1r4.ccpdev 02:31:05:~# ovs-vsctl list-ports br-conexus
    #patch-bond1-conexus
    #Chef::Log.info("AAAAAA '#{bridge[1]}'")
  end
end
