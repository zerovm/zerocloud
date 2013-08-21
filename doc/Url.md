# URL formats

Used in servlet configuration files

### Swift URL

<pre>
swift://&lt;account&gt;/&lt;container&gt;/&lt;object&gt;

&lt;account&gt; - account name, UTF-8, URL encoded, no / characters allowed
&lt;container&gt; - container name, UTF-8, URL encoded, no / characters allowed
&lt;object&gt; - object name, UTF-8, URL encoded
</pre>

Swift URL points to a Swift object path.
Can be used to fetch or execute objects from different account, if user has the permissions.

### File (image) URL

<pre>
file://&lt;image&gt;:&lt;path&gt;
file://&lt;path&gt;

&lt;image&gt; - system image name, if not used the user image device `/dev/image` will be assumed, UTF-8,
    URL encoded, no / characters allowed
&lt;path&gt; - file path, inside the image, UTF-8, URL encoded
</pre>

File URL points to a file inside a tar image.
If image name is supplied the file will be extracted from there, otherwise the default user image `/dev/image` will be assumed.
You must either use the existing sysimage name (see Configuration.md) or supply a path to user image in the request itself.

### Zvm (cluster) URL

<pre>
zvm://&lt;host&gt;:&lt;device&gt;

&lt;host&gt; - destination node name, domain name (alphanumeric and dashes only)
&lt;device&gt; - destination device name, can be supplied with or without `/dev` path
</pre>

Cluster URL points to a device file on another machine.
Can be used to easily connect specific local devices to remote ones (very useful for passing stdout to remote machine, for example).
Destination device file will be created on destination node instead of the default one `/dev/in/<node name>`.

