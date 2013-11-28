import re
import traceback
from swift import gettext_ as _
from zerocloud.common import SwiftPath, ZvmNode, ZvmChannel, is_zvm_path, \
    ACCESS_READABLE, ACCESS_CDR, ACCESS_WRITABLE, parse_location, ACCESS_RANDOM, \
    has_control_chars, DEVICE_MAP, is_swift_path


class ClusterConfigParsingError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


class ClusterConfigParser(object):
    def __init__(self, sysimage_devices, default_content_type,
                 read_limit, rbytes_limit, write_limit, wbytes_limit,
                 list_account_callback, list_container_callback):
        """
        Create a new parser instance

        :param sysimage_devices: list of known system image devices
        :param default_content_type: default content type to use for writable objects
        :param read_limit: limit for network channel read iops
        :param rbytes_limit: limit for network channel read bytes
        :param write_limit: limit for network channel write iops
        :param wbytes_limit: limit for network channel write bytes
        :param list_account_callback: callback function that can be called with
                (account_name, mask) to get a list of container names in account
                that match the mask regex
        :param list_container_callback: callback function that can be called with
                (account_name, container_name, mask) to get a list of object names in container
                that match the mask regex
        """
        self.sysimage_devices = sysimage_devices
        self.list_account = list_account_callback
        self.list_container = list_container_callback
        self.nodes = {}
        self.default_content_type = default_content_type
        self.node_id = 1
        self.write_limit = write_limit
        self.wbytes_limit = wbytes_limit
        self.read_limit = read_limit
        self.rbytes_limit = rbytes_limit

    def find_objects(self, path, **kwargs):
        """
        Find all objects in SwiftPath with wildcards

        :param path: SwiftPath object that has wildcards in url string
        :param **kwargs: optional arguments for list_container, list_account callbacks

        :returns list of object names, raises ClusterConfigParsingError on empty list
        :raises ClusterConfigParsingError: on all errors
        """
        temp_list = []
        if '*' in path.container:
            mask = re.compile(re.escape(path.container).replace('\\*', '.*'))
            try:
                containers = self.list_account(path.account, mask=mask, **kwargs)
            except Exception:
                raise ClusterConfigParsingError(_('Error querying object server '
                                                  'for account: %s') % path.account)
            if path.obj:
                obj = path.obj
                if '*' in obj:
                    obj = re.escape(obj).replace('\\*', '.*')
                mask = re.compile(obj)
            else:
                mask = None
            for container in containers:
                try:
                    obj_list = self.list_container(path.account,
                                                   container,
                                                   mask=mask, **kwargs)
                except Exception:
                    raise ClusterConfigParsingError(_('Error querying object server '
                                                      'for container: %s') % container)
                for obj in obj_list:
                    temp_list.append(SwiftPath.init(path.account, container, obj))
        else:
            obj = re.escape(path.obj).replace('\\*', '.*')
            mask = re.compile(obj)
            try:
                for obj in self.list_container(path.account,
                                               path.container,
                                               mask=mask, **kwargs):
                    temp_list.append(SwiftPath.init(path.account,
                                                    path.container,
                                                    obj))
            except Exception:
                raise ClusterConfigParsingError(_('Error querying object server '
                                                  'for container: %s') % path.container)
        if not temp_list:
            raise ClusterConfigParsingError(_('No objects found in path %s')
                                            % path.url)
        return temp_list

    def _get_new_node(self, zvm_node, index=0):
        if index == 0:
            new_name = zvm_node.name
        else:
            new_name = _create_node_name(zvm_node.name, index)
        new_node = self.nodes.get(new_name)
        if not new_node:
            new_node = zvm_node.copy(self.node_id, new_name)
            self.nodes[new_name] = new_node
            self.node_id += 1
        return new_node

    def _add_all_connections(self, node_name, connections, source_devices):
        if self.nodes.get(node_name):
            connect_node = self.nodes.get(node_name)
            for bind_name in connections:
                src_dev = None
                dst_dev = None
                if source_devices:
                    devices = source_devices.get(bind_name, None)
                    if devices:
                        (src_dev, dst_dev) = devices
                self._add_connection(connect_node, bind_name, src_dev, dst_dev)
        elif self.nodes.get(node_name + '-1'):
            j = 1
            connect_node = self.nodes.get(_create_node_name(node_name, j))
            while connect_node:
                for bind_name in connections:
                    src_dev = None
                    dst_dev = None
                    if source_devices:
                        devices = source_devices.get(bind_name, None)
                        if devices:
                            (src_dev, dst_dev) = devices
                    self._add_connection(connect_node, bind_name, src_dev, dst_dev)
                j += 1
                connect_node = self.nodes.get(
                    _create_node_name(node_name, j))
        else:
            raise ClusterConfigParsingError(_('Non existing node in connect string for node %s') % node_name)

    def parse(self, cluster_config, **kwargs):
        """
        Parse deserialized config and build separate job configs per node

        :param cluster_config: deserialized JSON cluster map
        :param **kwargs: optional arguments for list_container, list_account callbacks

        :raises ClusterConfigParsingError: on all errors
        """
        try:
            connect_devices = {}
            for node in cluster_config:
                zvm_node = ClusterConfigParser.create_node(node)
                node_count = node.get('count', 1)
                if isinstance(node_count, int) and node_count > 0:
                    pass
                else:
                    raise ClusterConfigParsingError(_('Invalid node count: %s') % str(node_count))
                file_list = node.get('file_list')
                read_list = []
                write_list = []
                other_list = []

                if file_list:
                    for f in file_list:
                        channel = ClusterConfigParser.create_channel(
                            f, zvm_node,
                            default_content_type=self.default_content_type)
                        if is_zvm_path(channel.path):
                            _add_connected_device(connect_devices, channel, zvm_node)
                            continue
                        if channel.access < 0:
                            if channel.device in self.sysimage_devices:
                                other_list.append(channel)
                                continue
                            raise ClusterConfigParsingError(_('Unknown device %s in %s')
                                                            % (channel.device, zvm_node.name))
                        if channel.access & ACCESS_READABLE:
                            read_list.insert(0, channel)
                        elif channel.access & ACCESS_CDR:
                            read_list.append(channel)
                        elif channel.access & ACCESS_WRITABLE:
                            write_list.append(channel)
                        else:
                            other_list.append(channel)

                    read_group = False
                    for chan in read_list:
                        if '*' in chan.path.path:
                            read_group = True
                            object_list = self.find_objects(chan.path, **kwargs)
                            read_mask = re.escape(chan.path.path).replace('\\*', '(.*)')
                            read_mask = re.compile(read_mask)
                            node_count = len(object_list)
                            for i in range(node_count):
                                new_path = object_list[i]
                                new_node = self._add_new_channel(zvm_node, chan, index=(i + 1), path=new_path)
                                new_node.store_wildcards(new_path, read_mask)
                        else:
                            if node_count > 1:
                                for i in range(1, node_count + 1):
                                    self._add_new_channel(zvm_node, chan, index=i)
                            else:
                                self._add_new_channel(zvm_node, chan)

                    for chan in write_list:
                        if chan.path and '*' in chan.path.url:
                            if read_group:
                                for i in range(1, node_count + 1):
                                    new_node = self.nodes.get(_create_node_name(zvm_node.name, i))
                                    new_url = _extract_stored_wildcards(chan.path, new_node)
                                    new_node.add_channel(channel=chan,
                                                         path=parse_location(new_url))
                            else:
                                for i in range(1, node_count + 1):
                                    new_name = _create_node_name(zvm_node.name, i)
                                    new_url = chan.path.url.replace('*', new_name)
                                    new_node = self._add_new_channel(zvm_node, chan, index=i,
                                                                     path=parse_location(new_url))
                                    new_node.wildcards = [new_name] * chan.path.url.count('*')
                        elif chan.path:
                            if node_count > 1:
                                raise ClusterConfigParsingError(_('Single path %s for multiple node '
                                                                  'definition: %s, please use wildcard')
                                                                % (chan.path.url, zvm_node.name))
                            self._add_new_channel(zvm_node, chan)
                        else:
                            if 'stdout' not in chan.device \
                                and 'stderr' not in chan.device:
                                raise ClusterConfigParsingError(_('Immediate response is not available '
                                                                  'for device %s') % chan.device)
                            if node_count > 1:
                                for i in range(1, node_count + 1):
                                    self._add_new_channel(zvm_node, chan, index=i,
                                                          content_type=f.get('content_type', 'text/html'))
                            else:
                                self._add_new_channel(zvm_node, chan,
                                                      content_type=f.get('content_type', 'text/html'))
                    for chan in other_list:
                        if chan.device in self.sysimage_devices:
                            chan.access = ACCESS_RANDOM | ACCESS_READABLE
                        else:
                            if not chan.path:
                                raise ClusterConfigParsingError(_('Path is required for device: %s') % chan.device)
                        if node_count > 1:
                            for i in range(1, node_count + 1):
                                self._add_new_channel(zvm_node, chan, index=i)
                        else:
                            self._add_new_channel(zvm_node, chan)
        except ClusterConfigParsingError:
            raise
        except Exception:
            print traceback.format_exc()
            raise ClusterConfigParsingError('Config parser internal error')

        for node in cluster_config:
            connection_list = node.get('connect')
            node_name = node.get('name')
            src_devices = connect_devices.get(node_name, None)
            if not connection_list:
                if src_devices:
                    connection_list = [connected_node for connected_node in src_devices.iterkeys()]
                else:
                    continue
            self._add_all_connections(node_name, connection_list, src_devices)

    def _add_new_channel(self, node, channel, index=0, path=None, content_type=None):
        new_node = self._get_new_node(node, index=index)
        new_node.add_channel(channel=channel, path=path,
                             content_type=content_type)
        return new_node

    @classmethod
    def create_channel(cls, channel, node, default_content_type=None):
        device = channel.get('device')
        if has_control_chars(device):
            raise ClusterConfigParsingError(_('Bad device name: %s in %s') % (device, node.name))
        path = parse_location(channel.get('path'))
        if not device:
            raise ClusterConfigParsingError(_('Must specify device for file in %s') % node.name)
        access = DEVICE_MAP.get(device, -1)
        mode = channel.get('mode', None)
        meta = channel.get('meta', {})
        content_type = channel.get('content_type', default_content_type)
        if access & ACCESS_READABLE and path:
            if not is_swift_path(path):
                raise ClusterConfigParsingError(_('Readable device must be a swift object'))
            if not path.account or not path.container:
                raise ClusterConfigParsingError(_('Invalid path %s in %s')
                                                % (path.url, node.name))
        return ZvmChannel(device, access, path=path,
                          content_type=content_type, meta_data=meta, mode=mode)

    @classmethod
    def create_node(cls, node_config):
        name = node_config.get('name')
        if not name:
            raise ClusterConfigParsingError(_('Must specify node name'))
        if has_control_chars(name):
            raise ClusterConfigParsingError(_('Invalid node name'))
        nexe = node_config.get('exec')
        if not nexe:
            raise ClusterConfigParsingError(_('Must specify exec stanza for %s') % name)
        exe = parse_location(nexe.get('path'))
        if not exe:
            raise ClusterConfigParsingError(_('Must specify executable path for %s') % name)
        if is_zvm_path(exe):
            raise ClusterConfigParsingError(_('Executable path cannot be a zvm path in %s') % name)
        args = nexe.get('args')
        env = nexe.get('env')
        if has_control_chars('%s %s %s' % (exe.url, args, env)):
            raise ClusterConfigParsingError(_('Invalid nexe property for %s') % name)
        replicate = node_config.get('replicate', 1)
        return ZvmNode(0, name, exe, args, env, replicate)

    def _add_connection(self, node, bind_name, src_device=None, dst_device=None):
        if not dst_device:
            dst_device = '/dev/in/' + node.name
        else:
            dst_device = _resolve_wildcards(node, dst_device)
        if self.nodes.get(bind_name):
            bind_node = self.nodes.get(bind_name)
            if bind_node is node:
                raise ClusterConfigParsingError('Cannot bind to itself: %s' % bind_name)
            bind_node.bind.append((node.name, dst_device))
            if not src_device:
                node.connect.append((bind_name, '/dev/out/' + bind_name))
            else:
                src_device = _resolve_wildcards(bind_node, src_device)
                node.connect.append((bind_name, src_device))
        elif self.nodes.get(bind_name + '-1'):
            i = 1
            bind_node = self.nodes.get(bind_name + '-1')
            while bind_node:
                if not bind_node is node:
                    bind_node.bind.append((node.name, dst_device))
                    if not src_device:
                        node.connect.append((bind_name + '-' + str(i),
                                             '/dev/out/' + bind_name + '-' + str(i)))
                    else:
                        src_device = _resolve_wildcards(bind_node, src_device)
                        node.connect.append((bind_name + '-' + str(i), src_device))
                i += 1
                bind_node = self.nodes.get(bind_name + '-' + str(i))
        else:
            raise ClusterConfigParsingError('Non-existing node in connect %s' % bind_name)

    def build_connect_string(self, node, node_count):
        """
        Builds connect strings from connection information stored in job config

        :param node: ZvmNode object we build strings for
        :param node_count: total count of nodes, including replicated ones
        """
        tmp = []
        for (dst, dst_dev) in node.bind:
            dst_id = self.nodes.get(dst).id
            dst_repl = self.nodes.get(dst).replicate
            proto = ';'.join(map(
                lambda i: 'tcp:%d:0' % (dst_id + i * node_count),
                range(dst_repl)
            ))
            tmp.append(
                ','.join([proto,
                          dst_dev,
                          '0,0',  # type = 0, sequential, etag = 0, not needed
                          str(self.read_limit),
                          str(self.rbytes_limit),
                          '0,0'])
            )
        node.bind = tmp
        tmp = []
        for (dst, dst_dev) in node.connect:
            dst_id = self.nodes.get(dst).id
            dst_repl = self.nodes.get(dst).replicate
            proto = ';'.join(map(
                lambda i: 'tcp:%d:' % (dst_id + i * node_count),
                range(dst_repl)
            ))
            tmp.append(
                ','.join([proto,
                          dst_dev,
                          '0,0',  # type = 0, sequential, etag = 0, not needed
                          '0,0',
                          str(self.write_limit),
                          str(self.wbytes_limit)])
            )
        node.connect = tmp


def _add_connected_device(devices, channel, zvm_node):
    if not devices.get(zvm_node.name, None):
        devices[zvm_node.name] = {}
    devices[zvm_node.name][channel.path.host] = (
        '/dev/' + channel.device, channel.path.device)


def _create_node_name(node_name, i):
    return '%s-%d' % (node_name, i)


def _resolve_wildcards(node, param):
    if param.count('*') > 0:
        for wc in getattr(node, 'wildcards', []):
            param = param.replace('*', wc, 1)
        if param.count('*') > 0:
            raise ClusterConfigParsingError('Cannot resolve wildcard for node %s' % node.name)
    return param


def _extract_stored_wildcards(path, node):
    new_url = path.url
    for wc in node.wildcards:
        new_url = new_url.replace('*', wc, 1)
    if new_url.count('*') > 0:
        raise ClusterConfigParsingError(_('Wildcards in input cannot be '
                                          'resolved into output path %s')
                                        % path)
    return new_url
