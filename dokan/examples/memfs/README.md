This is a simple memfs example for demonstrating the usage of the wrapper library.

Please note that it is still in early stage of development and contains many bugs. While normal browsering and file operations work in general, it fails a lot of [IFS tests](https://docs.microsoft.com/en-us/windows-hardware/test/hlk/testref/14b230f3-7eee-437e-ab2f-375b200de6f3) and may have unexpected behaviors in special cases. In addition, this example is NOT optimized for performance or memory usage, and doesn't have proper errror handling. So DO NOT use it in production environments.
