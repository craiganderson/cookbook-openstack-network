#
# Cookbook Name:: openstack-network
# Attributes:: default
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

# Set to some text value if you want templated config files
# to contain a custom banner at the top of the written file
default["openstack"]["network"]["custom_template_banner"] = "
# This file autogenerated by Chef
# Do not edit, changes will be overwritten
"

default["openstack"]["network"]["verbose"] = "False"
default["openstack"]["network"]["debug"] = "False"

# Gets set in the Network Endpoint when registering with Keystone
default["openstack"]["network"]["region"] = "RegionOne"
default["openstack"]["network"]["service_user"] = "quantum"
default["openstack"]["network"]["service_role"] = "admin"
default["openstack"]["network"]["service_name"] = "quantum"
default["openstack"]["network"]["service_type"] = "network"
default["openstack"]["network"]["description"] = "OpenStack Networking service"

# The rabbit user's password is stored in an encrypted databag
# and accessed with openstack-common cookbook library's
# user_password routine.  You are expected to create
# the user, pass, vhost in a wrapper rabbitmq cookbook.
default["openstack"]["network"]["rabbit_server_chef_role"] = "rabbitmq-server"
default["openstack"]["network"]["rabbit"]["username"] = "guest"
default["openstack"]["network"]["rabbit"]["vhost"] = "/"
default["openstack"]["network"]["rabbit"]["port"] = 5672
default["openstack"]["network"]["rabbit"]["host"] = "127.0.0.1"
default["openstack"]["network"]["rabbit"]["ha"] = false

# The database username for the quantum database
default["openstack"]["network"]["db"]["username"] = "quantum"

# Used in the Keystone authtoken middleware configuration
default["openstack"]["network"]["service_tenant_name"] = "service"
default["openstack"]["network"]["service_user"] = "quantum"
default["openstack"]["network"]["service_role"] = "admin"

# The default agent reporting interval
default["openstack"]["network"]["api"]["agent"]["agent_report_interval"] = 4

# The agent signing directory for api server
default["openstack"]["network"]["api"]["agent"]["signing_dir"] = "/var/lib/quantum/keystone-signing"

# Keystone PKI signing directory.
default["openstack"]["network"]["api"]["auth"]["cache_dir"] = "/var/cache/quantum/api"

# If bind_interface is set, the quantum API service will bind to the
# address on this interface and use the port in bind_port. Otherwise,
# it will bind to the API endpoint's host.
default["openstack"]["network"]["api"]["bind_interface"] = nil
default["openstack"]["network"]["api"]["bind_port"] = 9696

# logging attribute
default["openstack"]["network"]["syslog"]["use"] = false

# Whether or not we want to disable offloading
# on all the NIC interfaces (currently only supports
# ubuntu and debian).  This can help if openvswitch
# or nicira plugins are crashing the sdn routers
default['openstack']['network']['disable_offload'] = false

# configure quantum ha tool installation parameters
default["openstack"]["network"]["quantum_ha_cmd_cron"] = false
default["openstack"]["network"]["quantum_ha_cmd"] = "/usr/local/bin/quantum-ha-tool.py"
default["openstack"]["network"]["cron_l3_healthcheck"] = "*/1"
default["openstack"]["network"]["cron_replicate_dhcp"] = "*/1"

# the plugins to install on the server.  this will be
# quantum-plugin-%plugin% and the first plugin in the
# list should match the core plugin below
# N.B. this will be ignored on SUSE as all plugins are installed by
# default by the main openstack-quantum package
default["openstack"]["network"]["plugins"] = ['openvswitch', 'openvswitch-agent' ]

# the core plugin to use for quantum
default["openstack"]["network"]["core_plugin"] = "quantum.plugins.openvswitch.ovs_quantum_plugin.OVSQuantumPluginV2"

# The bridging interface driver.
#
# Options are:
#
#   - quantum.agent.linux.interface.OVSInterfaceDriver
#   - quantum.agent.linux.interface.BridgeInterfaceDriver
#

default["openstack"]["network"]["interface_driver"] = 'quantum.agent.linux.interface.OVSInterfaceDriver'

# maps the above driver to a plugin name
default["openstack"]["network"]["interface_driver_map"] = {
   'ovsinterfacedriver' => 'openvswitch',
   'bridgeinterfacedriver' => 'linuxbridge'
}

# The agent can use other DHCP drivers.  Dnsmasq is the simplest and requires
# no additional setup of the DHCP server.
default["openstack"]["network"]["dhcp_driver"] = 'quantum.agent.linux.dhcp.Dnsmasq'

# Use namespaces and optionally allow overlapping IPs. You
# must enable namespaces to use overlapping ips.  Also,
# you must have kernel build with CONFIG_NET_NS=y and
# iproute2 package that supports namespaces.
default["openstack"]["network"]["use_namespaces"] = "True"
default["openstack"]["network"]["allow_overlapping_ips"] = "False"

# use quantum root wrap
default["openstack"]["network"]["use_rootwrap"] = true

# ============================= DHCP Agent Configuration ===================

# The scheduler class to use for scheduling to DHCP agents
default["openstack"]["network"]["dhcp"]["scheduler"] = "quantum.scheduler.dhcp_agent_scheduler.ChanceScheduler"

# Override the default mtu setting given to virtual machines
# to 1454 to allow for tunnel and other encapsulation overhead.  You
# can adjust this from 1454 to 1500 if you do not want any lowering
# of the default guest MTU.
default["openstack"]["network"]["dhcp"]["dhcp-option"] = "26,1454"

# Number of seconds between sync of DHCP agent with Quantum API server
default["openstack"]["network"]["dhcp"]["resync_interval"] = 5

# OVS based plugins(Ryu, NEC, NVP, BigSwitch/Floodlight) that use OVS
# as OpenFlow switch and check port status
default["openstack"]["network"]["dhcp"]["ovs_use_veth"] = "True"

# The DHCP server can assist with providing metadata support on isolated
# networks. Setting this value to True will cause the DHCP server to append
# specific host routes to the DHCP request.  The metadata service will only
# be activated when the subnet gateway_ip is None.  The guest instance must
# be configured to request host routes via DHCP (Option 121).
default["openstack"]["network"]["dhcp"]["enable_isolated_metadata"] = "False"

# Allows for serving metadata requests coming from a dedicated metadata
# access network whose cidr is 169.254.169.254/16 (or larger prefix), and
# is connected to a Quantum router from which the VMs send metadata
# request. In this case DHCP Option 121 will not be injected in VMs, as
# they will be able to reach 169.254.169.254 through a router.
# This option requires enable_isolated_metadata = True
default["openstack"]["network"]["dhcp"]["enable_metadata_network"] = "False"

# On ubuntu precise, we build dnsmasq from source to fetch a more recent
# version of dnsmasq since a backport is not available. For any other
# platform, dnsmasq will be installed as a package
#
# See https://lists.launchpad.net/openstack/msg11696.html
default["openstack"]["network"]["dhcp"]["dnsmasq_url"] = "https://github.com/guns/dnsmasq/archive/v2.65.tar.gz"

# The name of the file we will fetch
default["openstack"]["network"]["dhcp"]["dnsmasq_filename"] = "v2.65.tar.gz"

# The checksum of the remote file we fetched
default["openstack"]["network"]["dhcp"]["dnsmasq_checksum"] = "f6cab8c64cb612089174f50927a05e2b"

# The package architecture that will be built which should match the
# archecture of the server this cookbook will run on which will be
# amd64 or i386
default["openstack"]["network"]["dhcp"]["dnsmasq_architecture"] = "amd64"

# The debian package version that the above tarball will produce
default["openstack"]["network"]["dhcp"]["dnsmasq_dpkgversion"] = "2.65-1"

# Upstream resolver to use
# This will be used by dnsmasq to resolve recursively
# but will not be used if the tenant specifies a dns
# server in their subnet
#
# Defaults are spread out across multiple, presumably
# reliable, upstream providers
#
# 8.8.8.8 is Google
# 209.244.0.3 is Level3
#
# May be a comma separated list of servers
default["openstack"]["network"]["dhcp"]["upstream_dns_servers"] = ["8.8.8.8", "209.244.0.3"]

# Set the default domain in dnsmasq
default["openstack"]["network"]["dhcp"]["default_domain"] = "openstacklocal"

# ============================= L3 Agent Configuration =====================

# The scheduler class to use for scheduling routers to L3 agents
default["openstack"]["network"]["l3"]["scheduler"] = "quantum.scheduler.l3_agent_scheduler.ChanceScheduler"

# If use_namespaces is set as False then the agent can only configure one router.
# This is done by setting the specific router_id.
default["openstack"]["network"]["l3"]["router_id"] = nil

# Each L3 agent can be associated with at most one external network.  This
# value should be set to the UUID of that external network.  If empty,
# the agent will enforce that only a single external networks exists and
# use that external network id
default["openstack"]["network"]["l3"]["gateway_external_network_id"] = nil

# Indicates that this L3 agent should also handle routers that do not have
# an external network gateway configured.  This option should be True only
# for a single agent in a Quantum deployment, and may be False for all agents
# if all routers must have an external network gateway
default["openstack"]["network"]["l3"]["handle_internal_only_routers"] = "True"

# Name of bridge used for external network traffic. This should be set to
# empty value for the linux bridge
default["openstack"]["network"]["l3"]["external_network_bridge"] = "br-ex"

# Interface to use for external bridge.
default["openstack"]["network"]["l3"]["external_network_bridge_interface"] = "eth1"

# TCP Port used by Quantum metadata server
default["openstack"]["network"]["l3"]["metadata_port"] = 9697

# Send this many gratuitous ARPs for HA setup. Set it below or equal to 0
# to disable this feature.
default["openstack"]["network"]["l3"]["send_arp_for_ha"] = 3

# seconds between re-sync routers' data if needed
default["openstack"]["network"]["l3"]["periodic_interval"] = 40

# seconds to start to sync routers' data after
# starting agent
default["openstack"]["network"]["l3"]["periodic_fuzzy_delay"] = 5

# ============================= Metadata Agent Configuration ===============

# The location of the Nova Metadata API service to proxy to (nil uses default)
default["openstack"]["network"]["metadata"]["nova_metadata_ip"] = "127.0.0.1"
default["openstack"]["network"]["metadata"]["nova_metadata_port"] = 8775

# The name of the secret databag containing the metadata secret
default["openstack"]["network"]["metadata"]["secret_name"] = "quantum_metadata_secret"


# ============================= LBaaS Agent Configuration ==================

# Enable or disable quantum loadbalancer
default["openstack"]["network"]["quantum_loadbalancer"] = false

# Plugin configuration path
default["openstack"]["network"]["lbaas_config_path"] = "/etc/quantum/plugins/services/agent_loadbalancer"

# Number of seconds between sync of LBaaS agent with Quantum API server
default["openstack"]["network"]["lbaas"]["periodic_interval"] = 10

# Set lbaas plugin
# Supported types are: "ovs" (ovs based plugins(OVS, Ryu, NEC, NVP, BigSwitch/Floodlight))
# and "linuxbridge".
default["openstack"]["network"]["lbaas_plugin"] = "ovs"

# ============================= OVS Plugin Configuration ===================

# Type of network to allocate for tenant networks. The default value 'local' is
# useful only for single-box testing and provides no connectivity between hosts.
# You MUST either change this to 'vlan' and configure network_vlan_ranges below
# or change this to 'gre' and configure tunnel_id_ranges below in order for tenant
# networks to provide connectivity between hosts. Set to 'none' to disable creation
# of tenant networks.
default["openstack"]["network"]["openvswitch"]["tenant_network_type"] = 'local'

# Comma-separated list of <physical_network>[:<vlan_min>:<vlan_max>] tuples enumerating
# ranges of VLAN IDs on named physical networks that are available for allocation.
# All physical networks listed are available for flat and VLAN provider network
# creation. Specified ranges of VLAN IDs are available for tenant network
# allocation if tenant_network_type is 'vlan'. If empty, only gre and local
# networks may be created
#
# Example: network_vlan_ranges = physnet1:1000:2999
default["openstack"]["network"]["openvswitch"]["network_vlan_ranges"] = nil

# Set to True in the server and the agents to enable support
# for GRE networks. Requires kernel support for OVS patch ports and
# GRE tunneling.
default["openstack"]["network"]["openvswitch"]["enable_tunneling"] = "False"

# Comma-separated list of <tun_min>:<tun_max> tuples
# enumerating ranges of GRE tunnel IDs that are available for tenant
# network allocation if tenant_network_type is 'gre'.
#
# Example: tunnel_id_ranges = 1:1000
default["openstack"]["network"]["openvswitch"]["tunnel_id_ranges"] = nil

# Do not change this parameter unless you have a good reason to.
# This is the name of the OVS integration bridge. There is one per hypervisor.
# The integration bridge acts as a virtual "patch bay". All VM VIFs are
# attached to this bridge and then "patched" according to their network
# connectivity
default["openstack"]["network"]["openvswitch"]["integration_bridge"] = 'br-int'

# Only used for the agent if tunnel_id_ranges (above) is not empty for
# the server.  In most cases, the default value should be fine
default["openstack"]["network"]["openvswitch"]["tunnel_bridge"] = "br-tun"

# Peer patch port in integration bridge for tunnel bridge (nil uses default)
default["openstack"]["network"]["openvswitch"]["int_peer_patch_port"] = nil

# Peer patch port in tunnel bridge for integration bridge (nil uses default)
default["openstack"]["network"]["openvswitch"]["tun_peer_patch_port"] = nil

# Uncomment this line for the agent if tunnel_id_ranges (above) is not
# empty for the server. Set local_ip to be the local IP address of
# this hypervisor or set the local_ip_interface parameter to use the IP
# address of the specified interface.  If local_ip_interface is set
# it will take precedence.
default["openstack"]["network"]["openvswitch"]["local_ip"] = "127.0.0.1"
default["openstack"]["network"]["openvswitch"]["local_ip_interface"] = nil

# Comma-separated list of <physical_network>:<bridge> tuples
# mapping physical network names to the agent's node-specific OVS
# bridge names to be used for flat and VLAN networks. The length of
# bridge names should be no more than 11. Each bridge must
# exist, and should have a physical network interface configured as a
# port. All physical networks listed in network_vlan_ranges on the
# server should have mappings to appropriate bridges on each agent.
#
# Example: bridge_mappings = physnet1:br-eth1
default["openstack"]["network"]["openvswitch"]["bridge_mappings"] = nil

# Firewall driver for realizing quantum security group function
default["openstack"]["network"]["openvswitch"]["fw_driver"] = "quantum.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver"

# ============================= LinuxBridge Plugin Configuration ===========

# Type of network to allocate for tenant networks. The
# default value 'local' is useful only for single-box testing and
# provides no connectivity between hosts. You MUST change this to
# 'vlan' and configure network_vlan_ranges below in order for tenant
# networks to provide connectivity between hosts. Set to 'none' to
# disable creation of tenant networks.
default["openstack"]["network"]["linuxbridge"]["tenant_network_type"] = 'local'

# Comma-separated list of <physical_network>[:<vlan_min>:<vlan_max>] tuples enumerating
# ranges of VLAN IDs on named physical networks that are available for allocation.
# All physical networks listed are available for flat and VLAN provider network
# creation. Specified ranges of VLAN IDs are available for tenant network
# allocation if tenant_network_type is 'vlan'. If empty, only gre and local
# networks may be created.
#
# Example: network_vlan_ranges = physnet1:1000:2999
default["openstack"]["network"]["linuxbridge"]["network_vlan_ranges"] = ""

# (ListOpt) Comma-separated list of
# <physical_network>:<physical_interface> tuples mapping physical
# network names to the agent's node-specific physical network
# interfaces to be used for flat and VLAN networks. All physical
# networks listed in network_vlan_ranges on the server should have
# mappings to appropriate interfaces on each agent.
#
# Example: physical_interface_mappings = physnet1:eth1
default["openstack"]["network"]["linuxbridge"]["physical_interface_mappings"] = ""

# ============================= BigSwitch Plugin Configuration =============

# Not really sure what this is...
default["openstack"]["network"]["bigswitch"]["servers"] = "localhost:8080"

# ============================= Brocade Plugin Configuration ===============

# username = <mgmt admin username>
default["openstack"]["network"]["brocade"]["switch_username"] = "admin"

# password = <mgmt admin password>
default["openstack"]["network"]["brocade"]["switch_password"] = "admin"

# address  = <switch mgmt ip address>
default["openstack"]["network"]["brocade"]["switch_address"] = "127.0.0.1"

# ostype   = NOS
default["openstack"]["network"]["brocade"]["switch_ostype"] = "NOS"

# physical_interface = <physical network name>
#
# Example:
# physical_interface = physnet1
default["openstack"]["network"]["brocade"]["physical_interface"] = "physnet1"

# (ListOpt) Comma-separated list of
# <physical_network>[:<vlan_min>:<vlan_max>] tuples enumerating ranges
# of VLAN IDs on named physical networks that are available for
# allocation. All physical networks listed are available for flat and
# VLAN provider network creation.
#
# Default: network_vlan_ranges =
# Example: network_vlan_ranges = physnet1:1000:2999
default["openstack"]["network"]["brocade"]["network_vlan_ranges"] = ""

# (ListOpt) Comma-separated list of
# <physical_network>:<physical_interface> tuples mapping physical
# network names to the agent's node-specific physical network
# interfaces to be used for flat and VLAN networks. All physical
# networks listed in network_vlan_ranges on the server should have
# mappings to appropriate interfaces on each agent.
#
# Example: physical_interface_mappings = physnet1:eth1
default["openstack"]["network"]["brocade"]["physical_interface_mappings"] = ""

# ============================= Cisco Plugin Configuration =================

# The module and class name path for the nexus plugin
default["openstack"]["network"]["cisco"]["nexus_plugin"] = "quantum.plugins.cisco.nexus.cisco_nexus_plugin_v2.NexusPlugin"

# The module and class name path for the vswitch plugin
default["openstack"]["network"]["cisco"]["vswitch_plugin"] = "quantum.plugins.openvswitch.ovs_quantum_plugin.OVSQuantumPluginV2"

# Start of the tenant VLAN range
default["openstack"]["network"]["cisco"]["vlan_start"] = 100

# End of the tenant VLAN range
default["openstack"]["network"]["cisco"]["vlan_end"] = 3000

# Prefix for tenant VLANs
default["openstack"]["network"]["cisco"]["vlan_name_prefix"] = "q-"

# Maximum number of ports
default["openstack"]["network"]["cisco"]["max_ports"] = 100
# Max number of port profiles
default["openstack"]["network"]["cisco"]["max_port_profiles"] = 65568

# Maximum number of networks
default["openstack"]["network"]["cisco"]["max_networks"] = 65568

# Module and class path for switch model
default["openstack"]["network"]["cisco"]["model_class"] = "quantum.plugins.cisco.models.virt_phy_sw_v2.VirtualPhysicalSwitchModelV2"

# Module and class path for VLAN network manager
default["openstack"]["network"]["cisco"]["manager_class"] = "quantum.plugins.cisco.segmentation.l2network_vlan_mgr_v2.L2NetworkVLANMgr"

# Module and class path for the Nexus driver
default["openstack"]["network"]["cisco"]["nexus_driver"] = "quantum.plugins.cisco.tests.unit.v2.nexus.fake_nexus_driver.CiscoNEXUSFakeDriver"

# For each Nexus switch, add a hash to the
# node["openstack"]["network"]["cisco"]["nexus_switches"] Hash,
# using the switch's IP address as the outer Hash key with each
# hash containing this information:
#
# - ssh_port=<ssh port>
# - username=<credential username>
# - password=<credential password>
# - hosts = [ (<hostname>,<port>), ... ]
#
# Example:
#
# node["openstack"]["network"]["cisco"]["nexus_switches"]["1.1.1.1"]["ssh_port"] = 22
# node["openstack"]["network"]["cisco"]["nexus_switches"]["1.1.1.1"]["username"] = "admin"
# node["openstack"]["network"]["cisco"]["nexus_switches"]["1.1.1.1"]["password"] = "mySecretPassword"
# node["openstack"]["network"]["cisco"]["nexus_switches"]["1.1.1.1"]["hosts"] = [ [ "compute1", "1/1" ],
#                                                                              [ "compute2", "1/2" ]]
#
#
# will write the following to the Cisco plugin config INI file:
# [NEXUS_SWITCH:1.1.1.1]
# compute1=1/1
# compute2=1/2
# ssh_port=22
# username=admin
# password=mySecretPassword
#
default["openstack"]["network"]["cisco"]["nexus_switches"] = {}

# ============================= Hyper-V Plugin Configuration ===============

# Type of network to allocate for tenant networks. The
# default value 'local' is useful only for single-box testing and
# provides no connectivity between hosts. You MUST change this to
# 'vlan' and configure network_vlan_ranges below in order for tenant
# networks to provide connectivity between hosts. Set to 'none' to
# disable creation of tenant networks.
default["openstack"]["network"]["hyperv"]["tenant_network_type"] = 'local'

# Comma-separated list of <physical_network>[:<vlan_min>:<vlan_max>] tuples enumerating
# ranges of VLAN IDs on named physical networks that are available for allocation.
# All physical networks listed are available for flat and VLAN provider network
# creation. Specified ranges of VLAN IDs are available for tenant network
# allocation if tenant_network_type is 'vlan'. If empty, only gre and local
# networks may be created.
#
# Example: network_vlan_ranges = physnet1:1000:2999
default["openstack"]["network"]["hyperv"]["network_vlan_ranges"] = ""

# Agent's polling interval in seconds
default["openstack"]["network"]["hyperv"]["polling_interval"] = 2

# (ListOpt) Comma separated list of <physical_network>:<vswitch>
# where the physical networks can be expressed with wildcards,
# e.g.: ."*:external".
# The referred external virtual switches need to be already present on
# the Hyper-V server.
# If a given physical network name will not match any value in the list
# the plugin will look for a virtual switch with the same name.
#
# Default: physical_network_vswitch_mappings = *:external
# Example: physical_network_vswitch_mappings = net1:external1,net2:external2
default["openstack"]["network"]["hyperv"]["physical_network_vswitch_mappings"] = "*:external"

# (StrOpt) Private virtual switch name used for local networking.
#
# Default: local_network_vswitch = private
# Example: local_network_vswitch = custom_vswitch
default["openstack"]["network"]["hyperv"]["local_network_vswitch"] = "private"

# ============================= Metaplugin Plugin Configuration ============

## This is list of flavor:quantum_plugins
# extension method is used in the order of this list
default["openstack"]["network"]["metaplugin"]["plugin_list"] = "openvswitch:quantum.plugins.openvswitch.ovs_quantum_plugin.OVSQuantumPluginV2,linuxbridge:quantum.plugins.linuxbridge.lb_quantum_plugin.LinuxBridgePluginV2"
default["openstack"]["network"]["metaplugin"]["l3_plugin_list"] = "openvswitch:quantum.plugins.openvswitch.ovs_quantum_plugin.OVSQuantumPluginV2,linuxbridge:quantum.plugins.linuxbridge.lb_quantum_plugin.LinuxBridgePluginV2"

# Default "flavor" for L2 and L3
default["openstack"]["network"]["metaplugin"]["default_flavor"] = "openvswitch"
default["openstack"]["network"]["metaplugin"]["default_l3_flavor"] = "openvswitch"

# ============================= Midonet Plugin Configuration ===============

# MidoNet API server URI
default["openstack"]["network"]["midonet"]["midonet_uri"] = "http://localhost:8080/midonet-api"

# MidoNet admin username
default["openstack"]["network"]["midonet"]["username"] = "admin"

# MidoNet admin password
default["openstack"]["network"]["midonet"]["password"] = "passw0rd"

# ID of the project that MidoNet admin user belongs to
default["openstack"]["network"]["midonet"]["project_id"] = "77777777-7777-7777-7777-777777777777"

# Virtual provider router ID
default["openstack"]["network"]["midonet"]["provider_router_id"] = "00112233-0011-0011-0011-001122334455"

# Virtual metadata router ID
default["openstack"]["network"]["midonet"]["metadata_router_id"] = "ffeeddcc-ffee-ffee-ffee-ffeeddccbbaa"

# ============================= NEC Plugin Configuration ===================

# Do not change this parameter unless you have a good reason to.
# This is the name of the OVS integration bridge. There is one per hypervisor.
# The integration bridge acts as a virtual "patch port". All VM VIFs are
# attached to this bridge and then "patched" according to their network
# connectivity.
default["openstack"]["network"]["nec"]["integration_bridge"] = "br-int"

# Agent's polling interval in seconds
default["openstack"]["network"]["nec"]["polling_interval"] = 2

# Firewall driver for realizing quantum security group function
default["openstack"]["network"]["nec"]["firewall_driver"] = "quantum.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver"

# Specify OpenFlow Controller Host, Port and Driver to connect.
default["openstack"]["network"]["nec"]["ofc_host"] = "127.0.0.1"
default["openstack"]["network"]["nec"]["ofc_port"] = 8888

# Drivers are in quantum/plugins/nec/drivers/ .
default["openstack"]["network"]["nec"]["ofc_driver"] = "trema"

# PacketFilter is available when it's enabled in this configuration
# and supported by the driver.
default["openstack"]["network"]["nec"]["ofc_enable_packet_filter"] = "true"

# ============================= Nicira Plugin Configuration ================

# User name for NVP controller
default["openstack"]["network"]["nicira"]["nvp_user"] = "admin"

# Password for NVP controller
default["openstack"]["network"]["nicira"]["nvp_password"] = "admin"

# Total time limit for a cluster request
# (including retries across different controllers)
default["openstack"]["network"]["nicira"]["req_timeout"] = 30

# Time before aborting a request on an unresponsive controller
default["openstack"]["network"]["nicira"]["http_timeout"] = 10

# Maximum number of times a particular request should be retried
default["openstack"]["network"]["nicira"]["retries"] = 2

# Maximum number of times a redirect response should be followed
default["openstack"]["network"]["nicira"]["redirects"] = 2

# Comma-separated list of NVP controller endpoints (<ip>:<port>). When port
# is omitted, 443 is assumed. This option MUST be specified, e.g.:
default["openstack"]["network"]["nicira"]["nvp_controllers"] = "xx.yy.zz.ww:443, aa.bb.cc.dd, ee.ff.gg.hh.ee:80"

# UUID of the pre-existing default NVP Transport zone to be used for creating
# tunneled isolated "Quantum" networks. This option MUST be specified, e.g.:
default["openstack"]["network"]["nicira"]["default_tz_uuid"] = "1e8e52cf-fa7f-46b0-a14a-f99835a9cb53"

# (Optional) UUID of the cluster in NVP.  It can be retrieved from NVP management
# console "admin" section.
default["openstack"]["network"]["nicira"]["nvp_cluster_uuid"] = "615be8e4-82e9-4fd2-b4b3-fd141e51a5a7"

# (Optional) UUID for the default l3 gateway service to use with this cluster.
# To be specified if planning to use logical routers with external gateways.
default["openstack"]["network"]["nicira"]["default_l3_gw_service_uuid"] = ""

# (Optional) UUID for the default l2 gateway service to use with this cluster.
# To be specified for providing a predefined gateway tenant for connecting their networks.
default["openstack"]["network"]["nicira"]["default_l2_gw_service_uuid"] = ""

# Name of the default interface name to be used on network-gateway.  This value
# will be used for any device associated with a network gateway for which an
# interface name was not specified
default["openstack"]["network"]["nicira"]["default_iface_name"] = "breth0"

# number of network gateways allowed per tenant, -1 means unlimited
default["openstack"]["network"]["nicira"]["quota_network_gateway"] = 5

# Maximum number of ports for each bridged logical switch
default["openstack"]["network"]["nicira"]["max_lp_per_bridged_ls"] = 64

# Maximum number of ports for each overlay (stt, gre) logical switch
default["openstack"]["network"]["nicira"]["max_lp_per_overlay_ls"] = 256

# Number of connects to each controller node.
default["openstack"]["network"]["nicira"]["concurrent_connections"] = 3

# Acceptable values for 'metadata_mode' are:
#   - 'access_network': this enables a dedicated connection to the metadata
#     proxy for metadata server access via Quantum router.
#   - 'dhcp_host_route': this enables host route injection via the dhcp agent.
# This option is only useful if running on a host that does not support
# namespaces otherwise access_network should be used.
default["openstack"]["network"]["nicira"]["metadata_mode"] = "access_network"

# ============================= PLUMGrid Plugin Configuration ==============

# This line should be pointing to the NOS server,
# for the PLUMgrid platform. In other deployments,
# this is known as controller
default["openstack"]["network"]["plumgrid"]["nos_server"] = "127.0.0.1"
default["openstack"]["network"]["plumgrid"]["nos_server_port"] = "<nos-port>"

# Authentification parameters for the NOS server.
# These are the admin credentials to manage and control
# the NOS server.
default["openstack"]["network"]["plumgrid"]["username"] = "<nos-admin-username>"
default["openstack"]["network"]["plumgrid"]["password"] = "<nos-admin-password>"
default["openstack"]["network"]["plumgrid"]["servertimeout"] = 5

# Name of the network topology to be deployed by NOS
default["openstack"]["network"]["plumgrid"]["topologyname"] = "<nos-topology-name>"

# ============================= Ryu Plugin Configuration ===================

# Do not change this parameter unless you have a good reason to.
# This is the name of the OVS integration bridge. There is one per hypervisor.
# The integration bridge acts as a virtual "patch port". All VM VIFs are
# attached to this bridge and then "patched" according to their network
# connectivity.
default["openstack"]["network"]["ryu"]["integration_bridge"] = "br-int"

# openflow_rest_api = <host IP address of ofp rest api service>:<port: 8080>
default["openstack"]["network"]["ryu"]["openflow_rest_api"] = "127.0.0.1:8080"

# tunnel key range: 0 < tunnel_key_min < tunnel_key_max
# VLAN: 12bits, GRE, VXLAN: 24bits
default["openstack"]["network"]["ryu"]["tunnel_key_min"] = 1
default["openstack"]["network"]["ryu"]["tunnel_key_max"] = "0xffffff"

# tunnel_ip = <ip address for tunneling>
# tunnel_interface = interface for tunneling
#                    when tunnel_ip is NOT specified, ip address is read
#                    from this interface
default["openstack"]["network"]["ryu"]["tunnel_ip"] = ""
default["openstack"]["network"]["ryu"]["tunnel_interface"] = "eth0"

# ovsdb_port = port number on which ovsdb is listening
#              ryu-agent uses this parameter to setup ovsdb.
#   ovs-vsctl set-manager ptcp:<ovsdb_port>
#   See set-manager section of man ovs-vsctl for details.
#   currently ptcp is only supported.
# ovsdb_ip = <host IP address on which ovsdb is listening>
# ovsdb_interface = interface for ovsdb
#                   when ovsdb_addr NOT specifiied, ip address is gotten
#                   from this interface
default["openstack"]["network"]["ryu"]["ovsdb_port"] = 6634
default["openstack"]["network"]["ryu"]["ovsdb_ip"] = ""
default["openstack"]["network"]["ryu"]["ovsdb_interface"] = "eth0"

# Firewall driver for realizing quantum security group function
default["openstack"]["network"]["ryu"]["firewall_driver"] = "quantum.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver"

# Agent's polling interval in seconds
default["openstack"]["network"]["ryu"]["polling_interval"] = 2

# platform-specific settings
case platform
when "fedora", "redhat", "centos" # :pragma-foodcritic: ~FC024 - won't fix this
  default["openstack"]["network"]["platform"] = {
    "user" => "quantum",
    "group" => "quantum",
    "mysql_python_packages" => [ "MySQL-python" ],
    "postgresql_python_packages" => ["python-psycopg2"],
    "nova_network_packages" => [ "openstack-nova-network" ],
    "quantum_packages" => [ "openstack-quantum" ],
    "quantum_client_packages" => [],
    "quantum_dhcp_packages" => [ "openstack-quantum" ],
    "quantum_dhcp_build_packages" => [],
    "quantum_l3_packages" => [ "quantum-l3-agent" ],
    "quantum_openvswitch_packages" => ["openvswitch"],
    "quantum_openvswitch_agent_packages" => ["openstack-quantum-openvswitch-agent"],
    "quantum_metadata_agent_packages" => [],
    "quantum_plugin_package" => "openstack-quantum-%plugin%",
    "quantum_server_packages" => [],
    "quantum_dhcp_agent_service" => "quantum-dhcp-agent",
    "quantum_l3_agent_service" => "quantum-l3-agent",
    "quantum_metadata_agent_service" => "quantum-metadata-agent",
    "quantum_openvswitch_service" => "openvswitch",
    "quantum_openvswitch_agent_service" => "openstack-quantum-openvswitch-agent",
    "quantum_server_service" => "quantum-server",
    "package_overrides" => ""
  }
when "suse"
  default["openstack"]["network"]["platform"] = {
    "user" => "openstack-quantum",
    "group" => "openstack-quantum",
    "mysql_python_packages" => ["python-mysql"],
    "postgresql_python_packages" => ["python-psycopg2"],
    "nova_network_packages" => ["openstack-nova-network"],
    "quantum_packages" => ["openstack-quantum"],
    "quantum_client_packages" => [],
    "quantum_dhcp_packages" => ["openstack-quantum-dhcp-agent"],
    "quantum_dhcp_build_packages" => [],
    "quantum_l3_packages" => ["openstack-quantum-l3-agent"],
    # plugins are installed by the main openstack-quantum package on SUSE
    "quantum_plugin_package" => "",
    "quantum_metadata_agent_packages" => ["openstack-quantum-metadata-agent"],
    "quantum_openvswitch_packages" => ["openvswitch-switch"],
    "quantum_openvswitch_agent_packages" => ["openstack-quantum-openvswitch-agent"],
    "quantum_metadata_agent_packages" => ["openstack-quantum-metadata-agent"],
    "quantum_server_packages" => [],
    "quantum_dhcp_agent_service" => "openstack-quantum-dhcp-agent",
    "quantum_l3_agent_service" => "openstack-quantum-l3-agent",
    "quantum_metadata_agent_service" => "openstack-quantum-metadata-agent",
    "quantum_openvswitch_service" => "openvswitch",
    "quantum_openvswitch_agent_service" => "openstack-quantum-openvswitch-agent",
    "quantum_server_service" => "openstack-quantum",
    "package_overrides" => ""
  }
when "ubuntu"
  default["openstack"]["network"]["platform"] = {
    "user" => "quantum",
    "group" => "quantum",
    "mysql_python_packages" => [ "python-mysqldb" ],
    "postgresql_python_packages" => [ "python-psycopg2" ],
    "nova_network_packages" => [ "nova-network" ],
    "quantum_lb_packages" => ["quantum-lbaas-agent", "haproxy"],
    "quantum_packages" => [ "quantum-common", "python-pyparsing", "python-cliff" ],
    "quantum_client_packages" => [ "python-quantumclient", "python-pyparsing" ],
    "quantum_dhcp_packages" => [ "quantum-dhcp-agent" ],
    "quantum_dhcp_build_packages" => [ "build-essential", "pkg-config", "libidn11-dev", "libdbus-1-dev", "libnetfilter-conntrack-dev", "gettext" ],
    "quantum_l3_packages" => [ "quantum-l3-agent" ],
    "quantum_openvswitch_packages" => [ "openvswitch-switch", "openvswitch-datapath-dkms", "bridge-utils" ],
    "quantum_openvswitch_agent_packages" => [ "quantum-plugin-openvswitch", "quantum-plugin-openvswitch-agent" ],
    "quantum_metadata_agent_packages" => [ "quantum-metadata-agent" ],
    "quantum_plugin_package" => "quantum-plugin-%plugin%",
    "quantum_server_packages" => ["quantum-server"],
    "quantum_dhcp_agent_service" => "quantum-dhcp-agent",
    "quantum_l3_agent_service" => "quantum-l3-agent",
    "quantum_metadata_agent_service" => "quantum-metadata-agent",
    "quantum_openvswitch_service" => "openvswitch-switch",
    "quantum_openvswitch_agent_service" => "quantum-plugin-openvswitch-agent",
    "quantum_server_service" => "quantum-server",
    "package_overrides" => "-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef'"
  }
end
