from ConfigParser import ConfigParser


def inject_before(some_list, item, target):
    for i, each in enumerate(some_list):
        if each == target:
            some_list.insert(i, item)
            break
    else:
        # just append to the list:
        some_list.append(item)


if __name__ == '__main__':
    cp = ConfigParser()
    cp.read('/etc/swift/object-server/1.conf')
    cp.add_section('filter:object-query')
    cp.set('filter:object-query', 'use',
           value='egg:zerocloud#object_query')
    cp.set('filter:object-query', 'zerovm_sysimage_devices',
           value='python2.7 /usr/share/zerovm/python.tar')

    pipeline = cp.get('pipeline:main', 'pipeline').split()
    inject_before(pipeline, 'object-query', 'object-server')
    cp.set('pipeline:main', 'pipeline', value=' '.join(pipeline))

    with open('/etc/swift/object-server/1.conf', 'w') as fp:
        cp.write(fp)

    cp = ConfigParser()
    cp.read('/etc/swift/proxy-server.conf')
    cp.add_section('filter:proxy-query')
    cp.set('filter:proxy-query', 'use',
           value='egg:zerocloud#proxy_query')
    cp.set('filter:proxy-query', 'zerovm_sysimage_devices',
           value='python2.7 /usr/share/zerovm/python.tar')

    pipeline = cp.get('pipeline:main', 'pipeline').split()
    inject_before(pipeline, 'proxy-query', 'proxy-server')
    cp.set('pipeline:main', 'pipeline', value=' '.join(pipeline))

    with open('/etc/swift/proxy-server.conf', 'w') as fp:
        cp.write(fp)
