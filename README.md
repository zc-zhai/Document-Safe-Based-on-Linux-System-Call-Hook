# Document Safe Based on Linux System Call Hook
The project aims at developing a Document Safe, based on Linux sys_call hook and Netlink communication between USER and CORE, including functions of verifying users as well as applications' identity, judging whether they can be accessible to files under protection of the Document Safe.<br>
The project can be divided into two parts: an application responsible for identity certification(sending results to the kernel via Netlink) and operations on the Document Safe; a kernel module implements sys_call hook(decides whether one could enter the Document Safe according to the identity certification results received).
## Security
* The application is the only process that has access to the Document Safe.
* The kernel module is hidden based on Rootkit, thus it cannot be detected by methods of `lsmod` or `sysfs`