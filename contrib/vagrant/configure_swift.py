import shutil
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
                      egg_name='zerocloud', extras=None):
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

        If `None`, don't modify the pipeline.
    """
    filt = 'filter:%s' % filter_name
    cp.add_section(filt)
    cp.set(filt, 'use', 'egg:%(egg)s#%(func)s' % dict(egg=egg_name,
                                                      func=func_name))

    if extras is not None:
        for k, v in extras.items():
            cp.set(filt, k, v)

    if inject_b4 is not None:
        pipeline = cp.get('pipeline:main', 'pipeline').split()
        pipeline = inject_before(pipeline, filter_name, inject_b4)
        cp.set('pipeline:main', 'pipeline', value=' '.join(pipeline))


def back_up(filename):
    """Make a copy of ``filename`` with the a .bak extension.
    """
    shutil.copyfile(filename, '%s.bak' % filename)


if __name__ == '__main__':
    obj_server = '/etc/swift/object-server/1.conf'
    proxy_server = '/etc/swift/proxy-server.conf'
    cont_server = '/etc/swift/container-server/1.conf'
    back_up(obj_server)
    back_up(proxy_server)
    back_up(cont_server)

    # Object server:
    cp = ConfigParser()
    cp.read(obj_server)
    # basic ZeroVM object server config
    config_add_filter(
        cp,
        'zerocloud-object-query',
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
    cp.read(proxy_server)
    # basic ZeroVM proxy server config
    config_add_filter(
        cp,
        'zerocloud-proxy-query',
        'proxy_query',
        'proxy-server',
        extras={
            'zerovm_sysimage_devices': ('python2.7 '
                                        '/usr/share/zerovm/python.tar'),
            'set log_name': 'zerocloud-proxy-query',
        }
    )
    # proxy server job chaining middleware
    config_add_filter(
        cp,
        'zerocloud-job-chain',
        'job_chain',
        'zerocloud-proxy-query',
        extras={'set log_name': 'zerocloud-job-chain'}
    )
    # install swauth
    config_add_filter(
        cp,
        'swauth',
        'swauth',
        None,
        egg_name='swauth',
        extras={
            'set log_name': 'swauth',
            'super_admin_key': 'swauthkey',
        }
    )
    # replace tempauth with swauth
    pipeline = cp.get('pipeline:main', 'pipeline')
    pipeline = pipeline.replace('tempauth', 'swauth')
    cp.set('pipeline:main', 'pipeline', pipeline)
    # allow account management (needed for swauth)
    cp.set('app:proxy-server', 'allow_account_management', 'true')

    with open(proxy_server, 'w') as fp:
        cp.write(fp)

    # Container server:
    cp = ConfigParser()
    cp.read(cont_server)
    config_add_filter(
        cp,
        'zerocloud-object-query',
        'object_query',
        'container-server',
        extras={
            'zerovm_sysimage_devices': 'python2.7 /usr/share/zerovm/python.tar'
        }
    )

    with open(cont_server, 'w') as fp:
        cp.write(fp)
