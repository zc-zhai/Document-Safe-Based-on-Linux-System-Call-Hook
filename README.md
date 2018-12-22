# Document Safe Based on Linux System Call Hook
The project aims at developing a Document Safe, based on Linux sys_call hook and Netlink communication between USER and CORE, including functions of verifying users as well as applications' identity, judging whether they can be accessible to files under protection of the Document Safe.<br>
The project can be divided into two parts: an application responsible for identity certification(sending results to the kernel via Netlink) and operations on the Document Safe; a kernel module implements sys_call hook(decides whether one can enter the Document Safe according to the identity certification results received).
## Environment
* Ubuntu 16.04 x86
* kernel version: 4.4.x
* Implemented by C.
## File Description
* Safe_Management_App.c: code of the application (USER)
* Linux_kernel_module.c: code of the kernel module (CORE)
* Makefile: console Linux_kernel_module.c and create .ko file so that it can be loaded into the core
## Implementation Details
At the beginning, the application includes functions of SignUp and SignIn. Once a valid user successfully logins in, the application will create Netlink communication with the kernel module and send message certifying user identity. Meanwhile, the kernel module has hooked original sys_call functions by getting sys_call_table and replacing their entrance addresses with hacked functions'. Hacked functions are different from original ones in that they contain an extra period of certification. Only if the kernel module has received certification message, the Document Safe is accessible. Moreover, the Document Safe is never exposed to other processes except the application, for the kernel module will dynamicly assess PID and only the process or child process of the application is legal.<br>
### Operations on Document Safe implemented by App
* tree
* ls
* open/edit/create
* delete
* mkdir
* rmdir
* copy
* rename/move
* chdir 
### Sys_call hooked by Kernel Module
* open
* unlink
* mkdir
* rmdir
* rename
* chdir
## Security
* The application is the only process that has access to the Document Safe.
* The kernel module is hidden based on Rootkit, thus it cannot be detected by methods of `lsmod` or `sysfs`.