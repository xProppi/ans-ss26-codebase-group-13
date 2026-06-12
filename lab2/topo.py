"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

# Class for an edge in the graph
class Edge:
	def __init__(self):
		self.lnode = None
		self.rnode = None
	
	def remove(self):
		self.lnode.edges.remove(self)
		self.rnode.edges.remove(self)
		self.lnode = None
		self.rnode = None

# Class for a node in the graph
class Node:
	def __init__(self, id, type):
		self.edges = []
		self.id = id
		self.type = type

	# Add an edge connected to another node
	def add_edge(self, node):
		edge = Edge()
		edge.lnode = self
		edge.rnode = node
		self.edges.append(edge)
		node.edges.append(edge)
		return edge

	# Remove an edge from the node
	def remove_edge(self, edge):
		self.edges.remove(edge)

	# Decide if another node is a neighbor
	def is_neighbor(self, node):
		for edge in self.edges:
			if edge.lnode == node or edge.rnode == node:
				return True
		return False


class Fattree:

	def __init__(self, num_ports):
		self.servers = []
		self.switches = []
		self.generate(num_ports)

	def generate(self, num_ports):

		pods = num_ports
		half = num_ports // 2

		# Store switches by pod
		edge_switches = []
		aggr_switches = []

		host_id = 0

		#
		# Create pod switches and hosts
		#
		for pod in range(pods):

			pod_edges = []
			pod_aggrs = []

			# Edge switches
			for i in range(half):
				sw = Node(f"e{pod}_{i}", "edge")
				self.switches.append(sw)
				pod_edges.append(sw)

			# Aggregation switches
			for i in range(half):
				sw = Node(f"a{pod}_{i}", "aggr")
				self.switches.append(sw)
				pod_aggrs.append(sw)

			edge_switches.append(pod_edges)
			aggr_switches.append(pod_aggrs)

			#
			# Connect edge <-> aggregation
			#
			for edge in pod_edges:
				for aggr in pod_aggrs:
					edge.add_edge(aggr)

			#
			# Add hosts under edge switches
			#
			for edge in pod_edges:
				for _ in range(half):

					host = Node(f"h{host_id}", "host")

					self.servers.append(host)

					edge.add_edge(host)

					host_id += 1

		#
		# Create core switches
		#
		cores = []

		num_cores = half * half

		for i in range(num_cores):
			core = Node(f"c{i}", "core")
			self.switches.append(core)
			cores.append(core)

		#
		# Connect aggregation <-> core
		#
		for pod in range(pods):

			for aggr_index in range(half):

				aggr = aggr_switches[pod][aggr_index]

				for j in range(half):

					core_index = aggr_index * half + j

					aggr.add_edge(cores[core_index])