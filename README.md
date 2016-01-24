# CLIP
Remote GPGPU with CLIP

![alt tag](http://mccardwell.net/extern/files/filehosting/static/clip-assets/CLIPSpot.png)

CLIP is a library that works in tandem with the OpenCL native libraries to allow OpenCL programs to create and launch kernels on remote hosts without having to install specialized software.  
CLIP contains two components: 
    1) the CLIP library that is integrated in an OpenCL application and 
    2) an executable client that is transferred to, and executed on, remote systems.  
CLIP handles all the back-end transfers and management of OpenCL objects so that programmers can focus on writing the important parts of their application.  The API was created to mimic the behavior of the OpenCL API; for example, to start a workload on a local system, a programmer uses "clEnqeueNDRangeKernel", but under CLIP, to start a workload on a remote system, "clipEnqueueNDRangeKernel" is used.  The change from "cl" to "clip" signifies that a remote workload is being started.  All data objects being processed are transferred over the network to and from the remote GPU for processing.

More information and documentation is coming soon!
For all other questions, send me a message and I'll try to get back as soon as possible.