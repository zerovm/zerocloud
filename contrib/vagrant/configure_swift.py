from ConfigParser import ConfigParser


def inject_before(some_list, item, target):
    # make a copy
    some_list = list(some_list)
    for i, each in enumerate(some_list):
        if each == target:
            some_list.insert(i, item)
            break
    else:
        raise RuntimeError("'%s' not found in pipeline" % target)
    return some_list


def config_add_filter(cp, filter_name, func_name, inject_b4,
                      extras=None):
    """
    :param cp:
        :class:`ConfigParser.ConfigParser` object
    :param filter_name:
        Name of the filter. This is the name that will be used to reference the
        filter in the pipeline configuration.
    :param func_name:
        Middleware function name.
    :param inject_b4:
        When inserting a filter into the pipeline, place the filter (indicated
        by `filter_name`) before `inject_b4`.
    """
    filt = 'filter:%s' % filter_name
    cp.add_section(filt)
    cp.set(filt, 'use', 'egg:zerocloud#%s' % func_name)

    if extras is not None:
        for k, v in extras.items():
            cp.set(filt, k, v)

    pipeline = cp.get('pipeline:main', 'pipeline').split()
    pipeline = inject_before(pipeline, filter_name, inject_b4)
    cp.set('pipeline:main', 'pipeline', value=' '.join(pipeline))


if __name__ == '__main__':
    # Object server:
    cp = ConfigParser()
    obj_server = '/etc/swift/object-server/1.conf'
    cp.read(obj_server)
    # basic ZeroVM object server config
    config_add_filter(
        cp,
        'object-query',
        'object_query',
        'object-server',
        extras={
            'zerovm_sysimage_devices': 'python2.7 /usr/share/zerovm/python.tar'
        }
    )
    # Set verbose logging on the object server
    cp.set('DEFAULT', 'log_level', 'DEBUG')
    with open(obj_server, 'w') as fp:
        cp.write(fp)

    # Proxy server:
    cp = ConfigParser()
    proxy_server = '/etc/swift/proxy-server.conf'
    cp.read(proxy_server)
    # basic ZeroVM proxy server config
    config_add_filter(
        cp,
        'proxy-query',
        'proxy_query',
        'proxy-server',
        extras={
            'zerovm_sysimage_devices': 'python2.7 /usr/share/zerovm/python.tar'
        }
    )
    # proxy server job chaining middleware
    config_add_filter(
        cp,
        'job-chain',
        'job_chain',
        'proxy-query'
    )
    with open(proxy_server, 'w') as fp:
        cp.write(fp)

    # Container server:
    cp = ConfigParser()
    cont_server = '/etc/swift/container-server/1.conf'
    cp.read(cont_server)
    config_add_filter(
        cp,
        'object-query',
        'object_query',
        'container-server',
        extras={
            'zerovm_sysimage_devices': 'python2.7 /usr/share/zerovm/python.tar'
        }
    )
    with open(cont_server, 'w') as fp:
        cp.write(fp)
