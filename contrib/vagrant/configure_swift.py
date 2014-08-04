from ConfigParser import ConfigParser


def inject_before(some_list, item, target):
    # make a copy
    some_list = list(some_list)
    for i, each in enumerate(some_list):
        if each == target:
            some_list.insert(i, item)
            break
    else:
        # just append to the list:
        some_list.append(item)
    return some_list


def config_add_filter(file_path, filter_name, func_name, inject_b4,
                      extras=None):
    cp = ConfigParser()
    cp.read(file_path)
    filt = 'filter:%s' % filter_name
    cp.add_section(filt)
    cp.set(filt, 'use', 'egg:zerocloud#%s' % func_name)

    if extras is not None:
        for k, v in extras.items():
            cp.set(filt, k, v)

    pipeline = cp.get('pipeline:main', 'pipeline').split()
    pipeline = inject_before(pipeline, filter_name, inject_b4)
    cp.set('pipeline:main', 'pipeline', value=' '.join(pipeline))

    with open(file_path, 'w') as fp:
        cp.write(fp)


if __name__ == '__main__':
    # basic ZeroVM object server config
    config_add_filter(
        '/etc/swift/object-server/1.conf',
        'object-query',
        'object_query',
        'object-server',
        extras={
            'zerovm_sysimage_devices': 'python2.7 /usr/share/zerovm/python.tar'
        }
    )

    # basic ZeroVM proxy server config
    config_add_filter(
        '/etc/swift/proxy-server.conf',
        'proxy-query',
        'proxy_query',
        'proxy-server',
        extras={
            'zerovm_sysimage_devices': 'python2.7 /usr/share/zerovm/python.tar'
        }
    )
