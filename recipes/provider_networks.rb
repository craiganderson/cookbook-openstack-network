node.override['openstack']['network']['provider_nets'] = {'conexus' => '400:499', 'extranet' => '100:200', 'netbond' => '200:300'}

bash "create_phys_bridge" do
  user "root"
  code "ovs-vsctl --may-exist add-br br-bond1 -- --may-exist add-port br-bond1 bond1"
end

node['openstack']['network']['provider_nets'].keys.each do |net|
 provider_net = "#{net}"
 log "#{provider_net}"
 vlan_range =  node["openstack"]["network"]["provider_nets"]["#{net}"]
 log "#{vlan_range}"
 bash "create_ovs_bridge" do
   user "root"
   code "ovs-vsctl --may-exist add-br br-#{net} -- --may-exist add-port br-#{net} patch-#{net} -- --may-exist add-port br-bond1 patch-bond1-#{net} -- set interface patch-#{net} type=patch options:peer=patch-bond1-#{net} -- set interface patch-bond1-#{net} type=patch options:peer=patch-#{net}"
 end
end

