# Servlet configuration format

JSON format describing a servlet configuration

<pre>
    [
        {
        <b>"name"</b>:"node name/alias, alphanumeric only", <b>required</b>
        <b>"exec"</b>:{    <b>required</b>
            <b>"path"</b>:"executable path, URL (see Url.md)", <b>required</b>
            "args":"executable command line", <i>optional</i>
            "env":{    <i>executable environment, optional</i>
                "key1":"value1",
                "key2":"value2"
                }
        },
        "file_list":[ <i>list of devices/files, optional</i>
            {
            <b>"device"</b>:"device name", <b>required</b>
            "path":"device file path, URL (see Url.md)", <i>optional</i>
            "content_type": "MIME type of the content", <i>optional, ignored for read-only devices</i>
            "meta": {   <i>metadata for the object, optional, ignored for read-only devices</i>
                "metakey1":"value1",
                "metakey2":"value2"
                }
            "mode": "changes stat() type of device, can be 'file', 'block', 'char' or 'pipe'", <i>optional</i>
            },
        ],
        "count":1, <i>number of nodes, optional</i>
        "connect":[ <i>destination nodes to connect to, optional</i>
            "nodename1",
            "nodename2"
        ],
        "replicate":1 <i>how many replicas of this node should run, optional</i>
        }
    ,
    ....
    ]
</pre>

### Rules

1. Allowed device names are:

    <pre>
    stdout
    stdin
    stderr
    input
    output
    image
    debug
    </pre>

    _All other device names are invalid_

    There are also 'system images' which are devices as well.
    If `zerovm_sysimage_devices` is set in proxy and object server config files
    you can use the device names you've set there in servlet config
    and they are added to the list of allowed device names.

2. `file_list[i].path` is optional
Only the following devices can be supplied without `path` property set

    <pre>
    stdout
    stderr
    output
    </pre>

    All other devices must have a path attribute

    If the device is a 'system image' it also does not have a path,
    its path is predefined in `zerovm_sysimage_devices` configuration directive

3. `file_list[i].path` can contain wild-card(s)
`*` character must be used as wild-card
Any number of wild-cards is allowed in one path
Wild-cards are expanded following the `/.*/` regex rule
If path contains wild-card the `count` is ignored
`debug` device cannot have a wild-card in path

4. If all devices in `file_list` do not contain path
or there are 0 devices in `file_list` a `count` should be supplied
If `count` is not supplied `count: 1` is assumed

5. If the following devices have wild-cards in path

    <pre>
    stdin
    input
    image
    </pre>

    Then the following devices (connected to the same mode) also must have wild-cards in path:

    <pre>
    stdout
    stderr
    output
    </pre>

    Or they can have no path attribute (if it's allowed for this device)

6. `connect` list represents one way directed connection from this node to the nodes in `connect`
The current node is a source of the connection and each node in `connect` is a destination
Node can be connected to itself if and only if its `count` > 1 implicitly (by having path with wild-card) or explicitly by having `count` property set

7. `args` represents a command line as a string
Command line should be supplied by user

8. `env` represents an execution environment as key->value hash
Keys must be unique
Keys and values should be supplied by user
Keys must be alphanumeric, cannot contain whitespace characters

9. There are the following device types

    <pre>
    <i>READABLE</i>
    <i>WRITABLE</i>
    <i>RANDOM</i>
    <i>SEQUENTIAL</i>
    <i>CDR</i>
    <i>NETWORK</i>
    </pre>

    Each device has the following type rules

    <pre>
    stdin: <i>SEQUENTIAL + READABLE</i>
    stdout: <i>SEQUENTIAL + WRITABLE</i>
    stderr: <i>SEQUENTIAL + WRITABLE</i>
    input: <i>RANDOM + READABLE</i>
    output: <i>RANDOM + WRITABLE</i>
    image: <i>CDR</i>
    debug: <i>NETWORK</i>
    </pre>

    All system image devices are <i>RANDOM + READABLE</i>

10. `debug` is a special network device
It must have `path` property set
Its path has the following semantics:
`proto://hostname:port`
Where proto must be one of:

    <pre>
    tcp
    udp
    </pre>

Port must be numeric
`hostname` must be a valid hostname, allowed characters: `alphanumeric`, `.`, `-`

11. Each `path` must start with `/` character
The following devices _must_ have existing, readable path:

    <pre>
    stdin
    input
    image
    </pre>

    `exec` property _must_ have existing, readable `path`
    `exec` property can have a relative path (not starting with `/`).
    If the `path` is relative it is assumed that executable file
    is archived inside `image` device or any of the `system image` devices.
    First the `image` device is checked for the relative path, then all the `system image`
    devices are checked in the order they appear in config file, the process stops when the file is found.

12. Device can have `content_type` property set. Its value will be posted as a `Content-Type` header for this object.
`content_type` makes sense only for `WRITABLE` devices as it won't change existing content types just write new ones.
The `Content-Type` for a device without a `path` property will be set for the HTTP response.
`content_type` property set for read-only devices will be ignored.

13. Device with `content_type: message/http` or `content_type: message/cgi` has a special meaning.
The output object of such device will be parsed as an HTTP response.
Headers taken from the parsed response will be supplied either to PUT if this object to be saved in object store,
or in the response if it is an immediate response object (no `path` set)
Only the following headers will be parsed from this object: `Content-Type` `X-Object-Meta-*`
`message/http` is for CGI NPH applications and `message/cgi` is for regular CGI applications.
CGI/1.1 is supported on server, CGI environment variables will be supplied to the application.

14. Device can have `meta` property set. `meta` contains meta-tag dictionary for this object.
The meta-tags will be written alongside the object when the object is saved.
Meta-tags will be sent within HTTP response if it is an immediate response object (no `path` set).
`meta` will be ignored for read-only objects.

15. Each node can have `replicate` property set. Default replication value is 1 (no replication).
This property supports `replicate: 2` and `replicate: 3` for double and triple replication respectively.
If it was set to > 1 additional copies of the node will run.
Zerovm will replicate channels data for these nodes and compare them at runtime.
If it encounters errors the data from these nodes will be temporarily ignored.
This feature allows cluster to be fault-tolerant and improves the cluster processing speeds slightly.
Zerocloud may decide to run specific nodes in replicated way even when it was not specified in the servlet config file.
It does so to add redundancy or set replicas for the resulting Swift objects directly.

16. Some applications may expect devices/channels to produce specific output when stat() is run on the descriptor.
You can change the type of the file with the `mode` property of the `device`.
The types are:
`file` - regular file
`char` - character device
`pipe` - FIFO pipe (default for standard channels `stdin` `stdout` `stderr`)
`block` - block device (default for all other channels)
The most useful combinations are: `file` instead of `block` and `char` instead of `pipe`.
Other combinations are supported but make little sense.


## Examples


#### Sort files in "/data/binary*.data"

----

<pre>
    [
        {
            "name":"sort",
            "exec":{"path":"swift://my_account/exec/sort.nexe"},
            "file_list":[
                {"device":"stdin","path":"swift://my_account/data/binary*.data"},
                {"device":"stdout","path":"swift://my_account/data/sorted*.data"},
                {"device":"stderr"}
            ],
            "args":"1048576"
        }
    ]
</pre>

- This job will look into `swift://my_account/data/binary*.data` path and match objects by wild-card.
- For each object it will create zerovm instance running `swift://my_account/exec/sort.nexe` object as nexe.
It will create `swift://my_account/data/sorted*.data` output objects, exactly the same count as input objects.
- Each output object will contain same characters instead of `*` that were matched in the original object.
    <pre>.../data/binary<b>\_log_345</b>.data -> .../data/sorted<b>\_log_345</b>.data</pre>
- Errors will be written to `/dev/stderr`, it does not have a path, therefore errors will be sent in HTTP response.
- Each nexe will be run as `sort.nexe 1048576` because `args` property was set, in case of sort it is a sort chunk size (specific to nexe, as it should be).

#### Create a map-reduce job

----

<pre>
    [
        {
            "name":"mapper",
            "exec":{"path":"swift://my_account/exec/maper.nexe"},
            "file_list":[
                {"device":"stdin","path":"swift://my_account/data/binary*.data"},
                {"device":"stderr"}
            ],
            "connect":["mapper","reducer"]
    },
        {
            "name":"reducer",
            "exec":{"path":"swift://my_account/exec/reducer.nexe"},
            "connect":["manager"],
            "count":5
    },
        {
            "name":"manager",
            "exec":{"path":"swift://my_account/exec/manager.nexe"},
            "file_list":[
                {"device":"stdout","path":"swift://my_account/data/mapred_result.data"},
                {"device":"stderr"}
            ]
    }
    ]
</pre>

- This one uses networking, `connect` property is set on some nodes.
- Mappers are connected to mappers (between themselves) and to reducers.
- Each `connect` means unidirectional connect, i.e. each mapper can send to each other mapper and to each reducer.
- Each reducer can send only to manager node.
- Manager node has no `count` and its `file_list` has no wild-cards, means there is exactly _one_ manager node.
- There are 5 reducers: `count: 5`.
- There are N mappers, it depends how many objects match the `swift://my_account/data/binary*.data` wildcard.
If there are 10 matching objects, there will be 10 mappers, each mapper will have 9 connections to 9 other mappers and 5 connections to each reducer.
- Each mapper will see something like this in its /dev/in/ directory:
    <pre>
    mapper-1
    mapper-2
    mapper-3
    mapper-4
    ........
    </pre>
    In /dev/out/ directory:
    <pre>
    mapper-1
    mapper-2
    mapper-3
    mapper-4
    ........
    reducer-1
    reducer-2
    ........
    </pre>
- The own node name can be found by reading `argv[0]` parameter (i.e. executable name).
Using its own name from `argv[0]` and names of all other connected nodes from traversing /dev/in and /dev/out, each node can have full network map of all nodes it needs to communicate with.
