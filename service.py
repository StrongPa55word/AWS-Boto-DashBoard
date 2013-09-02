from flask import Flask, flash, abort, redirect, url_for, request, render_template, make_response, json, Response
import os, sys
from boto.ec2.connection import EC2Connection
import config
import boto.ec2.elb
import boto
from boto.ec2 import *


app = Flask(__name__)


@app.route('/')
def index():

	list = []
	creds = config.get_ec2_conf()

	for region in config.region_list():
		conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
		zones = conn.get_all_zones()	
		instances = conn.get_all_instances()
		instance_count = len(instances)
		ebs = conn.get_all_volumes()
		ebscount = len(ebs)
		unattached_ebs = 0
		unattached_eli = 0
		active_count = 0
	
		for instance in instances:
			active = instances
			if active:
				active_count = active_count + 1	

		for vol in ebs:
			state = vol.attachment_state()
			if state == None:
				unattached_ebs = unattached_ebs + 1

		elis = conn.get_all_addresses()
		eli_count = len(elis)


		for eli in elis:
			instance_id = eli.instance_id
			if not instance_id:
				unattached_eli = unattached_eli + 1

		connelb = boto.ec2.elb.connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
		elb = connelb.get_all_load_balancers()
		elb_count = len(elb)
		list.append({ 'region' : region, 'zones': zones, 'instance_count' : instance_count, 'ebscount' : ebscount, 'unattached_ebs' : unattached_ebs, 'eli_count' : eli_count, 'unattached_eli' : unattached_eli, 'elb_count' : elb_count, 'active_count' : active_count})
		
	return render_template('index.html',list=list)

@app.route('/ebs_volumes/<region>/')
def ebs_volumes(region=None):
	creds = config.get_ec2_conf()
	conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	ebs = conn.get_all_volumes()
	ebs_vol = []	
	for vol in ebs:
		state = vol.attachment_state()
		if state == None:
			ebs_info = { 'id' : vol.id, 'size' : vol.size, 'iops' : vol.iops, 'status' : vol.status }
			ebs_vol.append(ebs_info)
	return render_template('ebs_volume.html',ebs_vol=ebs_vol,region=region)
			
@app.route('/ebs_volumes/<region>/delete/<vol_id>')
def delete_ebs_vol(region=None,vol_id=None):
	creds = config.get_ec2_conf()	
	conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	vol_id = vol_id.encode('ascii')
	vol_ids = conn.get_all_volumes(volume_ids=vol_id)
	for vol in vol_ids:
		vol.delete()
	return redirect(url_for('ebs_volumes', region=region))
	
@app.route('/elastic_ips/<region>/')
def elastic_ips(region=None):
	creds = config.get_ec2_conf()
	conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	elis = conn.get_all_addresses()
	un_eli = []
	for eli in elis:
		instance_id = eli.instance_id
		if not instance_id:
			eli_info = { 'public_ip' : eli.public_ip, 'domain' : eli.domain}
			un_eli.append(eli_info)
	return render_template('elastic_ip.html',un_eli=un_eli,region=region)

@app.route('/elastic_ips/<region>/delete/<ip>')
def delete_elastic_ip(region=None,ip=None):
	creds = config.get_ec2_conf()
	conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	ip = ip.encode('ascii')
	elis = conn.get_all_addresses(addresses=ip)

	for eli in elis:
		eli.release()
	return redirect(url_for('elastic_ips', region=region))
	

@app.route('/instance_active/<region>/')
def instance_active(region=None):
	creds = config.get_ec2_conf()
	conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	rsvs = conn.get_all_instances()
	instances = []
	for rsv in rsvs:
		insts = rsv.instances
		for inst in insts:
			active_info = { 'instance_id' : inst.id, 'Name' : inst.tags['Name'], 'Public_IP' : inst.ip_address,  'Private_IP' : inst.private_ip_address, 'Type':inst.get_attribute('instanceType')['instanceType'],	'Zone' : inst.placement, 'Subnet' : inst.subnet_id,	'VPC' : inst.vpc_id }
			instances.append(active_info)
	return render_template('active_instances.html',instances=instances)

@app.route('/elastic_lbs/<region>/')
def elastic_lbs(region=None):
	creds = config.get_ec2_conf()
	connelb = boto.ec2.elb.connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	load_balancers = connelb.get_all_load_balancers()
	elbs = []
  	for lb in load_balancers:
  		lb_info = { 'lb_name' : lb.name, 'lb_dns' : lb.dns_name, 'lb_instances' : lb.instances, 'lb_vpc' : lb.vpc_id, 'lb_sg' : lb.source_security_group }
  		elbs.append(lb_info)
	return render_template('active_lb.html',elbs=elbs)
			
if __name__ == '__main__':
	app.debug = True
	app.run(host='0.0.0.0',port=8080)
