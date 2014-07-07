# Zerocloud response

Here we describe zerocloud response headers and overall structure of
the response.

## HTTP response headers

All `X-Nexe-*` headers are "aggregating" ones. Which means that each
header a comma-separated list of values

### `X-Nexe-System`

Contains a list of node names for the job. Each node name is unique
for the job and specifies a separate ZeroVM instance.

Example: `X-Nexe-System: map-1,map-2,map-3,reduce-1,reduce-2`

### `X-Nexe-Status`

Contains a list of status lines from ZeroVM execution report.

Example: `X-Nexe-Status: ok,ok,ok,ok,ZeroVM did not run`

### `X-Nexe-Retcode`

Contains a list of application return codes from ZeroVM execution
report.

Example: `X-Nexe-Retcode: 0,2,0,0`

### `X-Nexe-Etag`

Contains a list of check sums for specific channels from ZeroVM
execution report.

Example: `X-Nexe-Etag: disabled,disabled`

### `X-Nexe-Validation`

Contains a list of validation statuses from ZeroVM execution report.

Example: `X-Nexe-Validation: 0,2,0,0`

*Note*: current validation statuses are: 

- 0 - success
- 1 - failure
- 2 - validator was not invoked

### `X-Nexe-Cdr-Line`

Contains an accounting report from ZeroVM execution report.

Example: `X-Nexe-Cdr-Line: 4.251, 3.994, 0.11 3.53 1262 75929984 34
199 0 0 0 0`

*Note*: current accounting stats format is: 

    <ttotal>, <tnode>, <node_acc>, <tnode>, <node_acc>, <tnode>, <node_acc>,.....

where:
    
    <ttotal> - total time, sec
    <tnode> - total node time, sec
    <node_acc> - node accounting line

*Note*: current node accounting line format is:

    <sys> <user> <reads> <rbytes> <writes> <wbytes> <nreads> <nrbytes> <nwrites> <nwbytes>

where:

    <sys> - system time, sec
    <user> - user time, sec
    <reads> - reads from disk
    <rbytes> - read bytes from disk
    <writes> - writes to disk
    <wbytes> - written bytes to disk
    <nreads> - reads from network
    <nrbytes> - read bytes from network
    <nwrites> - writes to network
    <nwbytes> - written bytes to network
    
### `X-Nexe-Error`

If errors were encountered during execution the `X-Nexe-Error` will be
populated. If no errors encountered the header will not be set on
response at all.

Example: `X-Nexe-Error: 404 Not found while fetching /a/c/o`

### `X-Nexe-Cached`

If the job was run from daemonized ZeroVM instance `X-Nexe-Cached`
will be set. Value will be always set to `true`. For non-daemon jobs
the header will not be set on response at all.

Example: `X-Nexe-Cached: true`

### `Etag`

Each job will have `Etag` header set to md5 hash of the current
timestamp.

Example: `Etag: 7afac020e1053dddced8997dd44097af`
