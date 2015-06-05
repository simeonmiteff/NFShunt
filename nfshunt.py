import os
import sys
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt # POX convention
from threading import Thread
from xml.etree import ElementTree
from io import BytesIO
from subprocess import Popen, PIPE
import json
import re

log = core.getLogger()

class NFShunt(object):
	def __init__(self, configfilename):
		self.connection = None
		self.config = None
		self.read_config(configfilename)
		core.openflow.addListeners(self)
		core.addListenerByName("GoingDownEvent", self._handle_GoingDownEvent)
		log.info("Launch complete, waiting for OF connection...")

	def read_config(self, configfilename):
		text = open(configfilename).read()
		try:
			self.config = json.loads(text)
			self.config['port_slow'] = {}
			self.config['port_fast'] = {}
			self.config['port_physdevin'] = {}
			for port in self.config['ports']:
			    self.config['port_slow'][port['slow']] = port
			    self.config['port_fast'][port['fast']] = port
			    self.config['port_physdevin'][port['physdevin']] = port
		except Exception as e:
			raise type(e), type(e)(e.message + ' happens with [%s] ' % text), sys.exc_info()[2]

	def conntrack_read_events(self, stdout, dummy):
		for line in iter(stdout.readline, b''):
			if line.find("flow")!=-1: # conntrack sometimes outputs non-XML lines
				try:
					etree = ElementTree.parse(BytesIO(line))
					ev = next(etree.iter())
				except:
					log.error('Failed to parse event data: {}'.format(ev_xml))
					continue
				if ev is None:
					continue
				self.try_shunting(ev)

	def try_shunting(self, flow):
		try:
			if not flow.findall(".//mark"): return
			eventtype = None
			if 'type' in flow.attrib:
				eventtype = flow.attrib['type']
			if eventtype in ["destroy"]: return
			mark = int(flow.find('.//meta[@direction="independent"]/mark').text)
			connid = int(flow.find('.//meta[@direction="independent"]/id').text)
			timeout = None
			timeouttag = flow.find('.//meta[@direction="independent"]/timeout')
			if timeouttag is not None: timeouttag.text
			state = None
			statetag = flow.find('.//meta[@direction="independent"]/state')
			if statetag is not None: state = statetag.text
			client_ip_tag = flow.find('.//meta[@direction="original"]/layer3/src')
			server_ip_tag = flow.find('.//meta[@direction="original"]/layer3/dst')
			client_port_tag = flow.find('.//meta[@direction="original"]/layer4/sport')
			server_port_tag = flow.find('.//meta[@direction="original"]/layer4/dport')
			if client_ip_tag is None or server_ip_tag is None or client_port_tag is None or server_port_tag is None:
				log.debug("Flow doesn't have all L3 and L4 info we need, ignoring.")
				return
			client_ip = client_ip_tag.text
			server_ip = server_ip_tag.text
			client_port = int(client_port_tag.text)
			server_port = int(server_port_tag.text)
		except Exception as e:
			raise type(e), type(e)(e.message + ' happens with [%s] ' % ElementTree.tostring(flow)), sys.exc_info()[2]
		flags = mark >> 28
		flags_physdevin = (flags & 0x4) >> 2
		flags_physdevout = (flags & 0x2) >> 1
		if not (flags_physdevin and flags_physdevout):
			log.debug("Flow is probably not via one of the slow path ports, ignoring.")
			return
		flags_flowmark = flags & 0x1
		physdevin = (mark & 0x0f000000) >> 24
		physdevout = (mark & 0x00f00000) >> 20
		flowmark = (mark & 0x000f0000) >> 16
		of_ports_in = self.config['port_physdevin'][physdevin]['fast']
		of_ports_out = self.config['port_physdevin'][physdevout]['fast']
		of_ports = [of_ports_in, of_ports_out]
		log.info("Conntrack event: type=%s mark=%s [flags=(pdin=%s,pdout=%s,flow=%s)] pdin=%s, pdout=%s, flowmark=%s, connid=%s, timeout=%s, state=%s, client=%s:%s, server=%s:%s" %
			tuple(map(str, [eventtype, hex(mark), flags_physdevin, flags_physdevout, flags_flowmark, physdevin, physdevout, flowmark,
				connid, timeout, state, client_ip, client_port, server_ip, server_port])))
		if flags_flowmark:
			if state in ["FIN_WAIT", "LAST_ACK", "TIME_WAIT"]:
				log.info("Not installing shunt because connection state is %s" % state)
			else:
				action = self.config['mark_actions'][str(flowmark)]
				log.info("User policy flowmark of %d detected in conntrack entry, action is: %s" % (flowmark, action))
				if action == "ignore":
					log.info("Doing nothing, because user policy asked us to ignore this flow.")
					# if default_no_shunting=true, this is equivalent to forcing via the slow path
				else:
					if action == "shunt":
						# For shunting we add flows to match, which send packets via fast path
						self.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=of_ports[1]), # if packet came from of_ports[0], send to of_ports[1]
							match=of.ofp_match(in_port=of_ports[0],dl_type=0x800,nw_dst=server_ip,nw_src=client_ip,
							nw_proto=pkt.ipv4.TCP_PROTOCOL,tp_src=client_port,tp_dst=server_port),
							priority=33000,idle_timeout=self.config['default_shunt_timeout'],
							flags=of.OFPFF_SEND_FLOW_REM,cookie=connid))
						self.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=of_ports[0]), # if packet came from of_ports[1], send to of_ports[0]
							match=of.ofp_match(in_port=of_ports[1],dl_type=0x800,nw_dst=client_ip,nw_src=server_ip,
							nw_proto=pkt.ipv4.TCP_PROTOCOL,tp_src=server_port,tp_dst=client_port),
							priority=33000,idle_timeout=self.config['default_shunt_timeout'],
							flags=of.OFPFF_SEND_FLOW_REM,cookie=connid))
						log.info("Shunt installed for server %s:%d [via port %d] -> client %s:%d [via port %d] - conntrack id %d"
							% (server_ip, server_port, of_ports[1], client_ip, client_port, of_ports[0], connid))
						log.info("Shunt installed for client %s:%d [via port %d] -> server %s:%d [via port %d] - conntrack id %d"
							% (client_ip, client_port, of_ports[0], server_ip, server_port, of_ports[1], connid))
						self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
					elif action == "block":
						# For blocking we add flows to match, which send packets to dev null
						self.connection.send(of.ofp_flow_mod(action=[], # empty action list == drop
							match=of.ofp_match(in_port=of_ports[0],dl_type=0x800,nw_dst=server_ip,nw_src=client_ip,
							nw_proto=pkt.ipv4.TCP_PROTOCOL,tp_src=client_port,tp_dst=server_port),
							priority=33000,idle_timeout=self.config['default_block_timeout'],
							flags=of.OFPFF_SEND_FLOW_REM,cookie=connid))
						self.connection.send(of.ofp_flow_mod(action=[], # empty action list == drop
							match=of.ofp_match(in_port=of_ports[1],dl_type=0x800,nw_dst=client_ip,nw_src=server_ip,
							nw_proto=pkt.ipv4.TCP_PROTOCOL,tp_src=server_port,tp_dst=client_port),
							priority=33000,idle_timeout=self.config['default_block_timeout'],
							flags=of.OFPFF_SEND_FLOW_REM,cookie=connid))
						log.info("Block installed for server %s:%d [via port %d] -> client %s:%d [via port %d] - conntrack id %d"
							% (server_ip, server_port, of_ports[1], client_ip, client_port, of_ports[0], connid))
						log.info("Block installed for client %s:%d [via port %d] -> server %s:%d [via port %d] - conntrack id %d"
							% (client_ip, client_port, of_ports[0], server_ip, server_port, of_ports[1], connid))
						self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
					# Now that we've installed flows, we must nuke the conntrack entry
					self.delete_conntrack(connid, client_ip, client_port, server_ip, server_port)


	def delete_conntrack(self, connid, client_ip, client_port, server_ip, server_port):
		log.info("Running command to delete conntrack entry %d" % connid)
		os.system("conntrack -D -p tcp -s %s --sport %d -d %s --dport %d" % (client_ip, client_port, server_ip, server_port))
		log.info("Done deleting.")

	def _handle_ConnectionUp(self, event):
		log.info("Switch %s is up.", dpidToStr(event.dpid))
		self.connection = event.connection
		if self.config['delete_flows_on_startup'] is True:
			log.info("Deleting existing flow entries.")
			self.connection.send(of.ofp_flow_mod(command=of.OFPFC_DELETE))
		if self.config['default_no_shunting'] is True:
			log.info("Adding flow entries for default slow-path switching.")
			for portgroup in self.config['ports']:
				self.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=portgroup['fast']),match=of.ofp_match(in_port=portgroup['slow'])))
				self.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=portgroup['slow']),match=of.ofp_match(in_port=portgroup['fast'])))
		log.info("Done with setup, now ready for conntrack events...")
		self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
		log.info("Controller running, checking for existing conntrack objects...")
		conntrack_existing = Popen(['conntrack','-L','-o','xml,id'], stdout=PIPE, bufsize=1)
		self.conntrack_read_events(conntrack_existing.stdout, True)
		log.info("Done checking existing objects, starting new conntrack events process...")
		conntrack_process = Popen(['conntrack','-E','-o','xml,id'], stdout=PIPE, bufsize=1)
		conntrack_thread = Thread(target=self.conntrack_read_events, args=(conntrack_process.stdout, True))
		conntrack_thread.daemon = True
		log.info("Starting conntrack event consumer thread...")
		conntrack_thread.start()

	def _handle_ConnectionDown(self, event):
		log.info("Switch %s is down.", dpidToStr(event.dpid))
		self.connection = None

	def _handle_FlowRemoved(self, event):
		log.info("Switch removed flow: reason=%d cookie=%d duration=%d/%d bytes=%d packets=%d" %
			(event.ofp.reason, event.ofp.cookie, event.ofp.duration_sec, event.ofp.duration_nsec, event.ofp.byte_count, event.ofp.packet_count))
		self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

	def _handle_FlowStatsReceived(self, event):
		log.debug("Flow stats follow:")
		for stat in event.stats:
			log.debug(self.format_stats(stat))

	def format_stats(self, stat):
		def safehex(n):
			if n is None:
				return "(None)"
			else:
				return hex(n)
		def append (obj, f, formatter=str, prefix=' '):
			try:
				v = getattr(obj, f)
				if v is None: return ''
				return prefix + f + "=" + formatter(v)
			except AttributeError:
				return ''
		outstr = 'match:['
		outstr += append(stat.match,'in_port', prefix='')
		outstr += append(stat.match,'dl_src')
		outstr += append(stat.match,'dl_dst')
		outstr += append(stat.match,'dl_vlan')
		outstr += append(stat.match,'dl_vlan_pcp')
		outstr += append(stat.match,'dl_type', safehex)
		outstr += append(stat.match,'nw_tos')
		outstr += append(stat.match,'nw_proto')
		outstr += append(stat.match,'nw_src')
		outstr += append(stat.match,'nw_dst')
		outstr += append(stat.match,'tp_src')
		outstr += append(stat.match,'tp_dst')
		outstr += '] actions:['
		first = True
		for action in stat.actions:
			if first:
				outstr += '['
				first = False
			else:
				outstr += ' ['
			outstr += append(action, 'type', prefix='')
			outstr += append(action, 'port')
			outstr += append(action, 'queue_id')
			outstr += append(action, 'vlan_vid')
			outstr += append(action, 'vlan_pcp')
			outstr += append(action, 'dl_addr')
			outstr += append(action, 'nw_addr')
			outstr += append(action, 'nw_tos')
			outstr += append(action, 'tp_port')
			outstr += append(action, 'vendor')
			outstr += ']'
		outstr += ']'
		outstr += ' duration_sec=' + str(stat.duration_sec)
		outstr += ' duration_nsec=' + str(stat.duration_nsec)
		outstr += ' priority=' + str(stat.priority)
		outstr += ' idle_timeout=' + str(stat.idle_timeout)
		outstr += ' hard_timeout=' + str(stat.hard_timeout)
		outstr += ' cookie=' + str(stat.cookie)
		outstr += ' packet_count=' + str(stat.packet_count)
		outstr += ' byte_count=' + str(stat.byte_count)
		return outstr

	def _handle_DownEvent(self, event):
		log.debug("Running Down event")

	def _handle_GoingDownEvent(self, event):
		log.debug("Running GoingDown event")
		if self.config['delete_flows_on_shutdown'] is True:
			log.info("Deleting flows before shutting down")
			self.connection.send(of.ofp_flow_mod(command=of.OFPFC_DELETE))

def launch (configfilename="nfshunt.json"):
	core.register("nfshunt", NFShunt(configfilename))
