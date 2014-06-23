# Hacking on ZeroCloud

The easiest way to install and test ZeroCloud is to set up a minimal Keystone
and Swift installation using DevStack. The guide will help get you started.

Note: We recommend installing DevStack and ZeroCloud on a virtual machine.
Something like VirtualBox or a cloud server instance will work quite nicely.


### Install DevStack

1. To install DevStack, clone the repo as instructed on http://devstack.org.
2. Create a `local.conf` file in the DevStack clone root with the following
   contents:

    ```
    [[local|localrc]]
    disable_all_services
    enable_service key mysql s-proxy s-object s-container s-account
    ```

3. Run `./stack.sh`.
4. Install the [python-swift-client](https://github.com/openstack/python-swiftclient)
   using your favorite package manager (pip, aptitude, etc.).
5. Source the `openrc` file the DevStack clone root. This will configure the
   various `OS_*` environment variables to allow you run client commands in a
   convenient way.
5. You can test that Swift is working by uploading a file. Here is an example:

    ```
    $ touch foo.txt
    $ swift upload test_container foo.txt
    foo.txt
    $ swift list
    test_container
    $ swift list test_container
    foo.txt
    ```


### Install ZeroCloud

1. Clone the ZeroCloud source:

    ```
    $ git clone https://github.com/zerovm/zerocloud.git
    ```

2. Install ZeroCloud globally:

    ```
    $ cd zerocloud
    $ sudo python setup.py install
    ```

3. Verify the installation. This import should succeed with any errors:

    ```
    $ python -c "import zerocloud"
    ```


### Configure Swift Pipelines

We now need to add ZeroCloud to the Swift pipeline.

1. Install the ZeroVM Python (2.7) distribution:

    ```
    $ sudo mkdir /usr/share/zerovm
    $ cd /usr/share/zerovm
    $ sudo wget http://packages.zerovm.org/zerovm-samples/python.tar
    ```

2. Add and enable the `object-query` middleware on the object server.
   First add this to the top of `/etc/swift/object-server/1.conf`:

    ```ini
    [filter:object-query]
    use = egg:zerocloud#object_query
    zerovm_sysimage_devices = python2.7 /usr/share/zerovm/python.tar
    #zerovm_debug = True
    ```

   This loads the middleware and configures the `python2.7` system
   image. Next you need to actually insert the middleware into the
   main pipeline. Edit the section so it says:

    ```ini
    [pipeline:main]
    pipeline = healthcheck recon object-query object-server
    ```

3. We now do the same for the proxy server. First we register the
   `object-proxy` filter by adding this to
   `/etc/swift/proxy-server.conf`:

    ```ini
    [filter:proxy-query]
    use = egg:zerocloud#proxy_query
    zerovm_sysimage_devices = python2.7 /usr/share/zerovm/python.tar
    ```

    We then insert the filter into the main pipeline. Here we inserted
    it just before the final `proxy-server` filter:

    ```ini
    [pipeline:main]
    pipeline = catch_errors gatekeeper healthcheck proxy-logging cache
      container_sync bulk slo dlo ratelimit crossdomain authtoken
      keystoneauth tempauth tempurl formpost staticweb
      container-quotas account-quotas proxy-logging proxy-query
      proxy-server
    ```

Additional ZeroCloud configuration options can be found in
[Configuration](/doc/Configuration.md/).


### Misc

If you are using VirtualBox and wish to interact with your DevStack
installation outside of the VM from your host machine, you will need to make a
few additional changes.

1. In your VirtualBox VM settings, go to Network -> Port Forwarding. Forward
   port 5000 -> 5000 (host -> guest) for Keystone and port 8080 -> 8080 for
   Swift.
2. DevStack creates an endpoint for Swift using the IP address of the VM (for
   example, 10.0.2.1). This is problematic since Keystone will point us to this
   address for using the Swift service. With the host -> guest port forwarding
   in place, we need to create the same endpoint using 127.0.0.1 (localhost).

   First, copy the `service_id` of the current Swift endpoint. The Swift
   endpoint is the one on port 8080:

    ```
    $ keystone endpoint-list
    ```

   Next, create a similar endpoint to the existing, except using 127.0.0.1 for
   the host:

    ```
    $ keystone endpoint-create --service-id=_service_id_ --publicurl="http://127.0.0.1:8080/v1/AUTH_\$(tenant_id)s" --internalurl="http://127.0.0.1:8080/v1/AUTH_\$(tenant_id)s" --adminurl=http://127.0.0.1:8080
    ```

   Verify that the endpoint was created. It should look identical to the
   original, except for the IP address:

    ```
    $ keystone endpoint-list
    ```

   Finally, delete the original endpoint:

    ```
    $ keystone endpoint-delete _id_
    ```

You should now be able to run Swift and [zpm](https://github.com/zerovm/zpm)
commands remotely to your DevStack installation on your VM.
