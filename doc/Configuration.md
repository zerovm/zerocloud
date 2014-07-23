# Zerocloud specific configuration

### proxyquery middleware

Configuration file: `proxy-server.conf`

    [filter:proxy-query]
    use = egg:zerocloud#proxy_query

Other configuration strings (default value after equals sign):

`zerovm_maxiops = 1073741824` - maximum number of read or write file iops per channel per each ZeroVM session, ex. how many times you can issue read() on STDIN device.

`zerovm_maxoutput = 1073741824` - maximum number of bytes you can write on each channel per ZeroVM session.

`zerovm_maxinput = 1073741824` - maximum number of bytes you can read from each channel per ZeroVM session.

`zerovm_maxconfig = 65536` - maximal length of the JSON job description in bytes, ex. max. size of `boot/system.map` file

`zerovm_ns_hostname = ''` - internal hostname or IP address of the proxy server, if unset it's guessed at runtime.

`zerovm_ns_maxpool = 1000` - maximum size of the threadpool for NameServer workers, if exceeded no new clustered jobs will start.

`max_upload_time = 86400` - how much time to wait for the client of POST request until it finished uploading data, in seconds.

`network_chunk_size = 65536` - middleware will stream all data using chunks of this length, in bytes.

`zerovm_uses_newest = no` - if set to `yes` Zerocloud will try to get the newest files when executing jobs (at the cost of more latency).

`zerovm_use_cors = no` - if set to `yes` will send `Access-Control-Allow-Origin` and `Access-Control-Expose-Headers` headers in response, if set on the container.

`zerovm_accounting_enabled = no` - if set to `yes` will enable storage of the accounting data (execution related) to a specific system account set by `user_stats_account` configuration variable.
The accounting data will be stored as `/v1/<user_stats_account>/<user account>/%Y/%m/%d.log`. Each new accounting line will be appended to the log file above (experimental feature).

`user_stats_account = userstats` - default account for storage of the ZeroVM billing/accounting data.

`zerovm_default_content_type = application/octet-stream` - default content type for all objects that are created by ZeroVM sessions and their `Content-Type` was not explicitly set in the job description file.

`zerovm_sysimage_devices = ''` - list of device name and path separated by blanks of `system image` devices. 
See below.

`zerovm_prevalidate = no` - if set to `yes` will run ZeroVM validation engine on all objects with `Content-Type: application/x-nexe` when PUT is issued for these. If the object is correctly validated, the object will be flagged valid and will not be revalidated on each execution. Because Swift ensures consistency on GET, there is no way to fool the system into serving unvalidated code by hammering server with PUTs.

`zerovm_daemons = ''` - list of json encoded job descriptions that will be used as daemon configs on the server startup. Format of the jobs is exactly as described in `Servlets.md`. The daemonized versions of the jobs will be lazy-loaded, i.e. no daemon will run until some user requests a job that matches one of the job configs passed in that variable.

`zerovm_timeout = 10` - time to wait for ZeroVM session to end, in seconds

### objectquery middleware

Configuration file: `object-server.conf`

    [filter:object-query]
    use = egg:zerocloud#object_query

Other configuration strings (default value after equals sign):

`zerovm_manifest_ver = 20130611` - manifest version of ZeroVM, will be changed from time to time, when format and version of ZeroVM manifest is updated.

`zerovm_exename = zerovm` - command line to execute ZeroVM hypervisor session, by default it's just a name of the executable. It's strongly advised to use a full path here.

`zerovm_maxpool = 10` - maximum number of simultaneously running ZeroVM sessions on this host, others are queued.

`zerovm_maxqueue = 3` - maximum number of ZeroVM execution requests in queue, waiting for their run.

`zerovm_timeout = 10` - timeout for ZeroVM session in pre-vaidation time, in seconds

`zerovm_kill_timeout = 1` - if after termination signal ZeroVM hypervisor is not dead Zerocloud waits this amount of time in seconds and then issues a kill signal.

`zerovm_maxiops = 1073741824` - maximum number of read or write file iops per channel per each ZeroVM session, ex. how many times you can issue read() on STDIN device.

`zerovm_maxoutput = 1073741824` - maximum number of bytes you can write on each channel per ZeroVM session.

`zerovm_maxinput = 1073741824` - maximum number of bytes you can read from each channel per ZeroVM session.

`zerovm_maxnexe = 268435456` - maximum size of the executable file, in bytes.

`zerovm_maxnexemem = 4294967296` - maximum size of memory allocation to each ZeroVM session.

`zerovm_sysimage_devices = ''` - list of device name and path separated by blanks of `system image` devices. Ex.:

    zerovm_sysimage_devices = device1 /path/to/device1.tar device2 /path/to/device2.tar

Each sysimage device is a ZeroVM image in tar file. It makes it simple to use global images for all users of the common software packages.

`zerovm_debug = no` - will gather manifest, nvram and other support files for each session inside `/tmp/zvm_debug/` directory, each session will have it's own dir named as the session transaction id (can be seen in Swift log).

`zerovm_perf = no` - will gather performance information and print it to object-server Swift log.

`zerovm_threadpools = default = WaitPool(10,3); cluster = PriorityPool(10,100);` - thread pool configuration, you can check out the various thread pool classes in [thread_pool.py](https://github.com/zerovm/zerocloud/blob/icehouse/zerocloud/thread_pool.py). The format is `name = PoolClass(.....); ....` you can add as many names and pool classes as you want. Right now only `default` and `cluster` pools are usable, `cluster` pool is used for clustered jobs and `default` pool - for any other job.

The following configuration parameters need to be copied from `app:object-server` config, if non-default:

- `devices`
- `disk_chunk_size`
- `keep_cache_size`
- `mb_per_sync`
- `mount_check`
- `reclaim_age`
- `replication_one_per_device`
- `replication_lock_timeout`
- `threads_per_disk`
- `disable_fallocate`
