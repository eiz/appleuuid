# appleuuid

Converts a UUID according to Apple's "Hardware UUID" generation algorithm.
You can use this to see what your Hardware UUID would be on OS X from Linux,
e.g. `appleuuid -l $(< /sys/class/dmi/id/product_uuid)`.

