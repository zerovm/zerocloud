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

`zerovm_sysimage_devices = ''` - list of device names (separated by blanks) that are considered a `system image` devices and were properly configured in `objectquery` middleware configuration file.
See below.

### objectquery middleware

Configuration file: `object-server.conf`

    [filter:object-query]
    use = egg:zerocloud#object_query

Other configuration strings (default value after equals sign):

`zerovm_manifest_ver = 20130611` - manifest version of ZeroVM, will be changed from time to time, when format and version of ZeroVM manifest is updated.

`zerovm_exename = zerovm` - command line to execute ZeroVM hypervisor session, by default it's just a name of the executable. It's strongly advised to use a full path here.

`zerovm_maxpool = 10` - maximum number of simultaneously running ZeroVM sessions on this host, others are queued.

`zerovm_maxqueue = 3` - maximum number of ZeroVM execution requests in queue, waiting for their run.

`zerovm_timeout = 5` - timeout for each ZeroVM session, in seconds. Hypervisor process is terminated after timeout.

`zerovm_kill_timeout = 1` - if after termination signal ZeroVM hypervisor is not dead Zerocloud waits this amount of time in seconds and then issues a kill signal.

`zerovm_maxiops = 1073741824` - maximum number of read or write file iops per channel per each ZeroVM session, ex. how many times you can issue read() on STDIN device.

`zerovm_maxoutput = 1073741824` - maximum number of bytes you can write on each channel per ZeroVM session.

`zerovm_maxinput = 1073741824` - maximum number of bytes you can read from each channel per ZeroVM session.

`zerovm_maxnexe = 268435456` - maximum size of the executable file, in bytes.

`zerovm_maxnexemem = 4294967296` - maximum size of memory allocation to each ZeroVM session.

`zerovm_sysimage_devices = ''` - list of device name and path separated by blanks of `system image` devices. Ex.:

    zerovm_sysimage_devices = device1 /path/to/device1.tar device2 /path/to/device2.tar

Each sysimage device is a ZeroVM image in tar file. It makes it simple to use global images for all users of the common software packages.
