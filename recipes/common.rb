# Encoding: utf-8
#
# Cookbook Name:: openstack-network
# Recipe:: common
#
# Copyright 2013, AT&T
# Copyright 2013, SUSE Linux GmbH
# Copyright 2013-2014, IBM Corp.
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

require 'uri'

# Make Openstack object available in Chef::Recipe
class ::Chef::Recipe
  include ::Openstack
end

platform_options = node['openstack']['network']['platform']

driver_name = node['openstack']['network']['interface_driver'].split('.').last.downcase
main_plugin = node['openstack']['network']['interface_driver_map'][driver_name]
core_plugin = node['openstack']['network']['core_plugin']

if node['openstack']['network']['syslog']['use']
  include_recipe 'openstack-common::logging'
end

platform_options['nova_network_packages'].each do |pkg|
  package pkg do
    action :purge
  end
end

platform_options['neutron_packages'].each do |pkg|
  package pkg do
    options platform_options['package_overrides']
    action :install
  end
end

db_type = node['openstack']['db']['network']['service_type']
platform_options["#{db_type}_python_packages"].each do |pkg|
  package pkg do
    options platform_options['package_overrides']
    action :install
  end
end

directory '/etc/neutron/plugins' do
  recursive true
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  mode 00700
  action :create
end

directory '/var/cache/neutron' do
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  mode 00700
  action :create
end

directory ::File.dirname node['openstack']['network']['api']['auth']['cache_dir'] do
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  mode 00700

  only_if { node['openstack']['auth']['strategy'] == 'pki' }
end

template '/etc/neutron/rootwrap.conf' do
  source 'rootwrap.conf.erb'
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  mode 00644
end

template '/etc/neutron/policy.json' do
  source 'policy.json.erb'
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  mode 00644

  notifies :restart, 'service[neutron-server]', :delayed
end

mq_service_type = node['openstack']['mq']['network']['service_type']

if mq_service_type == 'rabbitmq'
  rabbit_hosts = rabbit_servers if node['openstack']['mq']['network']['rabbit']['ha']
  mq_password = get_password 'user', node['openstack']['mq']['network']['rabbit']['userid']
elsif mq_service_type == 'qpid'
  mq_password = get_password 'user', node['openstack']['mq']['network']['qpid']['username']
end

identity_endpoint = endpoint 'identity-api'
identity_admin_endpoint = endpoint 'identity-admin'
identity_internal_endpoint = endpoint 'identity-api-internal'
auth_uri = ::URI.decode identity_internal_endpoint.to_s

auth_uri = auth_uri_transform identity_internal_endpoint.to_s, node['openstack']['network']['api']['auth']['version']

db_user = node['openstack']['db']['network']['username']
db_pass = get_password 'db', 'neutron'
sql_connection = db_uri('network', db_user, db_pass)

network_api_bind = endpoint 'network-api-bind'
service_pass = get_password 'service', 'openstack-network'

platform_options['neutron_client_packages'].each do |pkg|
  package pkg do
    action :upgrade
    options platform_options['package_overrides']
  end
end

# all recipes include common.rb, and some servers
# may just be running a subset of agents (like l3_agent)
# and not the api server components, so we ignore restart
# failures here as there may be no neutron-server process
service 'neutron-server' do
  service_name platform_options['neutron_server_service']
  supports status: true, restart: true
  ignore_failure true

  action :nothing
end

template '/etc/neutron/neutron.conf' do
  source 'neutron.conf.erb'
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  mode   00644
  variables(
    bind_address: network_api_bind.host,
    bind_port: network_api_bind.port,
    rabbit_hosts: rabbit_hosts,
    mq_service_type: mq_service_type,
    mq_password: mq_password,
    core_plugin: core_plugin,
    auth_uri: auth_uri,
    identity_internal_endpoint: identity_internal_endpoint,
    service_pass: service_pass,
    sql_connection: sql_connection
  )

  notifies :restart, 'service[neutron-server]', :delayed
end

template '/etc/neutron/api-paste.ini' do
  source 'api-paste.ini.erb'
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  mode   00640
  variables(
    auth_uri: auth_uri,
    identity_internal_endpoint: identity_internal_endpoint,
    service_pass: service_pass
  )

  notifies :restart, 'service[neutron-server]', :delayed
end

directory "/etc/neutron/plugins/#{main_plugin}" do
  recursive true
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  mode 00700
end

# For several plugins, the plugin configuration
# is required by both the neutron-server and
# ancillary services that may be on different
# physical servers like the l3 agent, so we assume
# the plugin configuration is a "common" file

template_file = nil
plugin_file = '/etc/neutron/plugin.ini'

case main_plugin
when 'bigswitch'

  template_file =  '/etc/neutron/plugins/bigswitch/restproxy.ini'

  template template_file do
    source 'plugins/bigswitch/restproxy.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
  end

when 'brocade'

  template_file = '/etc/neutron/plugins/brocade/brocade.ini'

  template template_file do
    source 'plugins/brocade/brocade.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
  end

when 'cisco'

  template_file = '/etc/neutron/plugins/cisco/cisco_plugins.ini'

  template template_file do
    source 'plugins/cisco/cisco_plugins.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
  end

when 'hyperv'

  template_file = '/etc/neutron/plugins/hyperv/hyperv_neutron_plugin.ini.erb'

  template template_file do
    source 'plugins/hyperv/hyperv_neutron_plugin.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
  end

when 'linuxbridge'

  template_file = '/etc/neutron/plugins/linuxbridge/linuxbridge_conf.ini'
  # retrieve the local interface for tunnels
  if node['openstack']['network']['linuxbridge']['local_ip_interface'].nil?
    local_ip = node['openstack']['network']['linuxbridge']['local_ip']
  else
    local_ip = address_for node['openstack']['network']['linuxbridge']['local_ip_interface']
  end

  template template_file do
    source 'plugins/linuxbridge/linuxbridge_conf.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644
    variables(
      local_ip: local_ip
    )

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
    if node.run_list.expand(node.chef_environment).recipes.include?('openstack-network::linuxbridge')
      notifies :restart, 'service[neutron-plugin-linuxbridge-agent]', :delayed
    end
  end

when 'midonet'

  template_file = '/etc/neutron/plugins/metaplugin/metaplugin.ini'

  template template_file do
    source 'plugins/metaplugin/metaplugin.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
  end

when 'ml2'

  template_file = '/etc/neutron/plugins/ml2/ml2_conf.ini'
  if node['openstack']['network']['openvswitch']['local_ip_interface'].nil?
    local_ip = node['openstack']['network']['openvswitch']['local_ip']
  else
    local_ip = address_for node['openstack']['network']['openvswitch']['local_ip_interface']
  end

  compute_node_boolean = false
  if node.run_list.expand(node.chef_environment).roles.include?('openstack-compute-worker')
    compute_node_boolean = true
  end

  template template_file do
    source 'plugins/ml2/ml2_conf.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644
    variables(
      local_ip: local_ip,
      compute_node_boolean: compute_node_boolean
    )

    notifies :create, "link[#{plugin_file}]", :immediately
    if node.run_list.expand(node.chef_environment).roles.include?('openstack-base::openstack-controller-ccp') or node.run_list.expand(node.chef_environment).roles.include?('openstack-base::openstack-controller')
      notifies :restart, 'service[neutron-server]', :delayed
    end
    if node.run_list.expand(node.chef_environment).recipes.include?('openstack-network::openvswitch')
      notifies :restart, 'service[neutron-plugin-openvswitch-agent]', :delayed
    end
  end

  link "/etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini" do
    to template_file
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    action :create
  end

when 'nec'

  template_file = '/etc/neutron/plugins/nec/nec.ini'

  template template_file do
    source 'plugins/nec/nec.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
  end

when 'nicira'

  template_file = '/etc/neutron/plugins/nicira/nvp.ini'

  template template_file do
    source 'plugins/nicira/nvp.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
  end

when 'openvswitch'

  template_file = '/etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini'
  # retrieve the local interface for tunnels
  if node['openstack']['network']['openvswitch']['local_ip_interface'].nil?
    local_ip = node['openstack']['network']['openvswitch']['local_ip']
  else
    local_ip = address_for node['openstack']['network']['openvswitch']['local_ip_interface']
  end

  template template_file do
    source 'plugins/openvswitch/ovs_neutron_plugin.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644
    variables(
      local_ip: local_ip
    )
    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
    if node.run_list.expand(node.chef_environment).recipes.include?('openstack-network::openvswitch')
      notifies :restart, 'service[neutron-plugin-openvswitch-agent]', :delayed
    end
  end

when 'plumgrid'

  template_file = '/etc/neutron/plugins/plumgrid/plumgrid.ini'

  template template_file do
    source 'plugins/plumgrid/plumgrid.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
  end

when 'ryu'

  template_file = '/etc/neutron/plugins/ryu/ryu.ini'

  template template_file do
    source 'plugins/ryu/ryu.ini.erb'
    owner node['openstack']['network']['platform']['user']
    group node['openstack']['network']['platform']['group']
    mode 00644

    notifies :create, "link[#{plugin_file}]", :immediately
    notifies :restart, 'service[neutron-server]', :delayed
  end

end

link plugin_file do
  to template_file
  owner node['openstack']['network']['platform']['user']
  group node['openstack']['network']['platform']['group']
  action :nothing
  only_if { platform? %w{fedora redhat centos} }
end

node.set['openstack']['network']['plugin_config_file'] = template_file

template '/etc/default/neutron-server' do
  source 'neutron-server.erb'
  owner 'root'
  group 'root'
  mode 00644
  variables(
    plugin_config: template_file
  )
  only_if do
    node.run_list.expand(node.chef_environment).recipes.include?('openstack-network::server')
    platform?(%w{ubuntu debian})
  end
end
