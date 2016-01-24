//
//  CLIPFramework.h
//  CLIPFramework
//
//  Created by Carter McCardwell on 1/15/16.
//  Copyright © 2016 Carter McCardwell. All rights reserved.
//

//Note: only functions that should be exposed to users are
//included in this header, look at the C file for the back-
//end operations

#ifndef CLIPFramework_h
#define CLIPFramework_h

#include <stdio.h>
#include <OpenCL/OpenCL.h>

//Structure that contains the hosts
//that are avaliable to use within CLIP
//DO NOT WRITE TO THE CONNECTION
struct connection {
    int id;         //ID that represents the connection
    char* host;     //The 'nice' hostname
    int status;     //Status of connection
    int reciv_socket; //Internal sockets
};

//Initialization function
//Args: -hostfile: the text file that contains the hosts to use
//      -a_silent: if 0, suppress CLIP's output
//      -num_hosts: will write the number of hosts that are obtained from the hostfile to variable
//      -connection_str: will return an array of connection's that represent the CLIP contexts
int init_clip(char* hostfile, int a_silent, int *num_hosts, struct connection **connection_str);

cl_int clipGetPlatformIDs(int connection_id, cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms);
cl_int clipGetDeviceIDs(int connection_id, cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices);
cl_context clipCreateContext(int connection_id, cl_uint num_devices, cl_device_id *devices, cl_int *err);
cl_command_queue clipCreateCommandQueue(int connection_id, cl_context context, cl_device_id device, cl_int *err);
cl_program clipCreateProgramWithSource(int connection_id, cl_context context, char *src_str, cl_int *err);
cl_int clipBuildProgram(int connection_id, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options);
cl_int clipGetBuildLog(int connection_id, cl_program program, cl_device_id device, char **log);
cl_mem clipCreateBuffer(int connection_id, cl_context context, cl_mem_flags flags, size_t size, void *host_ptr, cl_int *errcode_ret);
cl_kernel clipCreateKernel(int connection_id, cl_program program, const char *kernel_name, cl_int *errcode_ret);
cl_int clipSetKernelArg(int connection_id, cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value);
cl_int clipEnqueueNDRangeKernel(int connection_id, cl_command_queue queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_size, const size_t *local_work_size);
void clipFinish(int connection_id, cl_command_queue queue, int max_wait_cycles);
cl_int clipEnqueueReadBuffer(int connection_id, cl_command_queue queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t cb, void *ptr);
int clipReleaseClient(int connection_id);
cl_int clipReleaseMemObject(int connection_id, cl_mem mem);

#endif /* CLIPFramework_h */