WIP Filesystem API hooks to redirect disk access to memory buffer.   
For snapshot fuzzing   

Usage:   

```c
HookerInit();
HookerHookFile(fPath, g_buf, g_buflen, FILE_ATTRIBUTE_NORMAL);
```
