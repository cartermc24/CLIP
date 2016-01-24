//
//  CLIPClient.c
//  CLIPFramework
//
//  Created by Carter McCardwell on 1/16/16.
//  Copyright © 2016 Carter McCardwell. All rights reserved.
//

//Required imports
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <OpenCL/OpenCL.h>
//End required imports

//Definitions
#define PORT "4889"  // The communications port
#define BACKLOG 1    // how many pending connections queue will hold (only 1 at a time)
#define MAXDATASIZE 5000
//End definitions

//Commands
#define HANDSHAKE 10 //Initial connection
#define SRC_TRANSMIT_COMPILE_CL 11 //Local host is sending OpenCL source to remote host for compilation
#define REQ_RELEASE_CLIENT 12 //Graceful disconnect
#define REQ_CL_GET_PLATFORM_ID 13 //"clGetPlatformIDs"
#define REQ_CL_GET_DEVICE_ID 14 //"clGetDeviceIDs"
#define REQ_CL_CREATE_CONTEXT 15 //"clCreateContext"
#define REQ_CL_CREATE_COMMAND_QUEUE 16 //"clCreateCommandQueue"
#define REQ_CL_CREATE_PROGRAM_SRC 17 //"clCreateProgramWithSource"
#define REQ_CL_BUILD_PROGRAM 18 //"clBuildProgram"
#define REQ_CL_GET_BUILD_LOG 19 //"clGetBuildInfo simplified"
#define REQ_CL_CREATE_BUFFER 20 //"clCreateBuffer"
#define REQ_CL_CREATE_KERNEL 21 //"clCreateKernel"
#define REQ_CL_SET_KERNEL_ARG 22 //"clSetKernelArg"
#define REQ_CL_ENQUEUE_ND_RANGE_KERNEL 23 //"clEnqueueNDRangeKernel"
#define REQ_CL_FINISH 24 //"clFinish"
#define REQ_CL_ENQUEUE_READ_BUFFER 25 //"clEnqueueReadBuffer"
#define REQ_CL_RELEASE_MEM_OBJECT 26 //"clReleaseMemObject"
////Responses
#define ACKNOLEDGE 20 //OK Response, no data returned
#define FAILURE 21 //Error processing response
#define UNSOL_PROCESS_COMPLETED 22 //Unsolicited completed notification
#define DATA_CONTAINED 23 //Packet contains data being returned to the host
#define UNSOL_DISCONNECT 24 //Unsolicited disconnect notification
#define RSP_DIR_REQUEST 25 //Response to a direct request
//End commands/responses

//Globals
int bind_host_socket = -1;
int send_client_socket = -1;
char cur_addr[INET6_ADDRSTRLEN];
int in_session = 0;
//End globals

//Standard Unions
#pragma pack(1)
union {
    char data[4];
    cl_uint u;
} reassemble_cluint;
union {
    char data[4];
    cl_int u;
} reassemble_clint;
union {
    char data[8];
    size_t s;
    cl_mem_flags f;
    cl_mem m;
    cl_program p;
    cl_context c;
    cl_device_type t;
    cl_device_id d;
    cl_platform_id pl;
    cl_kernel k;
    cl_command_queue q;
} reassemble_8byte;
#pragma pack(0)
//End standard unions

//Structures
#pragma pack(1)
struct CLIP_response_packet
{
    int code;
    int ext;
    size_t data_len;
    void *data;
};
#pragma pack(0)
//End structures

void assert(int e)
{
    switch (e)
    {
        case -1:
            fprintf(stderr, "[CLIPClient]: Fatal error, terminating\n");
            exit(1);
            break;
    }
}

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    
    while(waitpid(-1, NULL, WNOHANG) > 0);
    
    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int enable_server()
{
    int sock_id = -1;
    struct addrinfo srt, *service_info, *current;
    struct sigaction action;
    int err, yes = 1;
    
    memset(&srt, 0, sizeof(srt));
    srt.ai_family = AF_UNSPEC;
    srt.ai_socktype = SOCK_STREAM;
    srt.ai_flags = AI_PASSIVE;
    
    if ((err = getaddrinfo(NULL, PORT, &srt, &service_info)) != 0)
    {
        fprintf(stderr, "[CLIPClient]: Error during self-identification / [%s]\n", gai_strerror(err));
        return -1;
    }
    
    for (current = service_info; current != NULL; current = current->ai_next)
    {
        if ((sock_id = socket(current->ai_family, current->ai_socktype, current->ai_protocol)) == -1)
        {
            continue;
        }
        if (setsockopt(sock_id, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            fprintf(stderr, "[CLIPClient]: Error configuring socket\n");
            return -1;
        }
        if (bind(sock_id, current->ai_addr, current->ai_addrlen) == -1)
        {
            close(sock_id);
            continue;
        }
        break;
    }
    
    freeaddrinfo(service_info);
    
    if (current == NULL)
    {
        fprintf(stderr, "[CLIPClient]: Failed to bind to port\n");
        return -1;
    }
    
    if (listen(sock_id, BACKLOG) == -1)
    {
        fprintf(stderr, "[CLIPClient]: Failed to start listener\n");
        return -1;
    }
    
    action.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &action, NULL) == -1)
    {
        fprintf(stderr, "[CLIPClient]: Signaling error\n");
        return -1;
    }
    
    printf("[CLIPClient]: Waiting for connections...\n");
    bind_host_socket = sock_id;
    return 0;
}

int send_packet(struct CLIP_response_packet packet)
{
    if (send(send_client_socket, &packet, sizeof(packet), 0) == -1)
    {
        return -3;
    }
    return 0;
}

int hold_for_connection()
{
    struct sockaddr_storage client_addr;
    socklen_t sin_size;
    char addr[INET6_ADDRSTRLEN];
    int client_sock_id;
    
    while(1) {  // main accept() loop
        sin_size = sizeof(client_addr);
        client_sock_id = accept(bind_host_socket, (struct sockaddr *)&client_addr, &sin_size);
        if (client_sock_id == -1) {
            fprintf(stderr, "[CLIPClient]: Error accepting connection\n");
            continue;
        }
        
        inet_ntop(client_addr.ss_family,
                  get_in_addr((struct sockaddr *)&client_addr),
                  addr, sizeof(addr));
        printf("[CLIPClient]: Request from %s\n", addr);
        send_client_socket = client_sock_id;
        
        struct CLIP_response_packet response;
        
        if (!in_session)
        {
            int i = INET6_ADDRSTRLEN;
            for (; i --> 0;) { cur_addr[i] = addr[i]; }
            in_session = 1;
            //Create handshake packet
            response.code = HANDSHAKE;
            response.ext = -1;
            response.data = NULL;
            response.data_len = 0;
            assert(send_packet(response));
            printf("[CLIPClient]: Connected\n");
            return 0;
        }
    }
    return 0;
}

void process_request(struct CLIP_response_packet request)
{
    struct CLIP_response_packet response;
    cl_int result, err;
    cl_context context;
    cl_program program;
    cl_kernel kernel;
    char *buffer;
    int i = 0;
    switch (request.code)
    {
        case REQ_CL_GET_PLATFORM_ID:;
            cl_uint num_platforms;
            cl_platform_id platform_ids;
            result = clGetPlatformIDs(request.ext, &platform_ids, &num_platforms);
            int packet_size = sizeof(cl_int) + sizeof(cl_uint) + num_platforms*sizeof(cl_platform_id);
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_GET_PLATFORM_ID;
            response.data_len = packet_size;
            send_packet(response);
            send(send_client_socket, &result, sizeof(cl_int), 0);
            send(send_client_socket, &platform_ids, sizeof(cl_platform_id)*num_platforms, 0);
            send(send_client_socket, &num_platforms, sizeof(cl_uint), 0);
            printf("[CLIPClient]: Successfully processed request [getPlatformIDs]\n");
            break;
        case REQ_CL_GET_DEVICE_ID:;
            cl_platform_id platform;
            cl_device_type type;
            cl_uint num_entries;
            buffer = (char *)request.data;
            if (request.data_len != sizeof(cl_platform_id)+sizeof(cl_device_type)+sizeof(cl_uint))
            {
                fprintf(stderr, "[CLIPClient]: Data invalid for request [getDeviceIDs]\n");
                return;
            }
            for (; i < sizeof(cl_platform_id); i++) { reassemble_8byte.data[i] = buffer[i]; }
            platform = reassemble_8byte.pl;
            i = 0;
            for (; i < sizeof(cl_device_type); i++) { reassemble_8byte.data[i] = buffer[i+sizeof(cl_platform_id)]; }
            type = reassemble_8byte.t;
            i = 0;
            for (; i < sizeof(cl_uint); i++) { reassemble_cluint.data[i] = buffer[i+sizeof(cl_platform_id)+sizeof(cl_device_type)]; }
            num_entries = reassemble_cluint.u;
            i = 0;
            
            cl_device_id *ids = (cl_device_id *)malloc(sizeof(cl_device_id)*num_entries);
            cl_uint num_ids;
            
            result = clGetDeviceIDs(platform, type, num_entries, ids, &num_ids);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_GET_DEVICE_ID;
            response.data_len = sizeof(cl_int) + sizeof(cl_uint) + num_ids*sizeof(cl_device_id);
            send_packet(response);
            send(send_client_socket, &result, sizeof(cl_int), 0);
            send(send_client_socket, &num_ids, sizeof(cl_uint), 0);
            for (; i < num_ids; i++) { send(send_client_socket, (ids + i), sizeof(cl_device_id), 0); }
            free(ids);
            
            printf("[CLIPClient]: Successfully processed request [getDeviceIDs]\n");
            break;
        case REQ_CL_CREATE_CONTEXT:;
            cl_uint num_devices = request.ext;
            cl_device_id *device_ids = (cl_device_id *)request.data;
            
            context = clCreateContext(0, num_devices, device_ids, NULL, NULL, &err);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_CREATE_CONTEXT;
            response.data_len = sizeof(cl_int) + sizeof(cl_context);
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_int), 0);
            send(send_client_socket, &context, sizeof(cl_context), 0);
            printf("[CLIPClient]: Successfully processed request [createContext]\n");
            break;
        case REQ_CL_CREATE_COMMAND_QUEUE:;
            cl_command_queue queue;
            cl_context context;
            cl_device_id device;
            //Check length
            buffer = (char *)request.data;
            i = 0;
            for (; i < sizeof(cl_context); i++) { reassemble_8byte.data[i] = buffer[i]; }
            context = reassemble_8byte.c;
            i = 0;
            for (; i < sizeof(cl_device_id); i++) { reassemble_8byte.data[i] = buffer[i+sizeof(cl_context)]; }
            device = reassemble_8byte.d;
            queue = clCreateCommandQueue(context, device, 0, &err);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_CREATE_COMMAND_QUEUE;
            response.data_len = sizeof(cl_int) + sizeof(cl_command_queue);
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_int), 0);
            send(send_client_socket, &queue, sizeof(cl_command_queue), 0);
            printf("[CLIPClient]: Successfully processed request [createCommandQueue]\n");
            break;
        case REQ_CL_CREATE_PROGRAM_SRC:;
            buffer = (char *)request.data;
            i = 0;
            for (; i < sizeof(cl_context); i++) { reassemble_8byte.data[i] = buffer[i]; }
            context = reassemble_8byte.c;
            buffer = buffer + sizeof(cl_context);
            unsigned long length = strlen(buffer);
            program = clCreateProgramWithSource(context, 1, &buffer, &length, &err);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_CREATE_PROGRAM_SRC;
            response.data_len = sizeof(cl_int) + sizeof(cl_program);
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_int), 0);
            send(send_client_socket, &program, sizeof(cl_program), 0);
            printf("[CLIPClient]: Successfully processed request [createProgramWithSource]\n");
            break;
        case REQ_CL_BUILD_PROGRAM:;
            int num_device;
            buffer = (char *)request.data;
            
            i = 0;
            for (; i < sizeof(cl_program); i++) { reassemble_8byte.data[i] = buffer[i]; }
            program = reassemble_8byte.p;
            buffer += sizeof(cl_program);
            
            i = 0;
            for (; i < sizeof(cl_uint); i++) { reassemble_cluint.data[i] = buffer[i]; }
            num_device = reassemble_cluint.u;
            buffer += sizeof(cl_uint);
            cl_device_id *dev_ids = (cl_device_id *)malloc(sizeof(cl_device_id) * num_device);
            
            int j = 0;
            for (; j < num_device; j++)
            {
                i = 0;
                for (; i < sizeof(cl_device_id); i++) { reassemble_8byte.data[i] = buffer[i]; }
                dev_ids[j] = reassemble_8byte.d;
                buffer += sizeof(cl_device_id);
            }
            
            if (strlen(buffer) <= 0) { buffer = NULL; }
            err = clBuildProgram(program, num_device, dev_ids, buffer, NULL, NULL);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_BUILD_PROGRAM;
            response.data_len = sizeof(cl_int);
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_int), 0);
            printf("[CLIPClient]: Successfully processed request [buildProgram]\n");
            free(dev_ids);
            break;
        case REQ_CL_GET_BUILD_LOG:;
            buffer = (char *)request.data;
            
            i = 0;
            for (; i < sizeof(cl_program); i++) { reassemble_8byte.data[i] = buffer[i]; }
            program = reassemble_8byte.p;
            buffer += sizeof(cl_program);
            
            i = 0;
            for (; i < sizeof(cl_device_id); i++) { reassemble_8byte.data[i] = buffer[i]; }
            device = reassemble_8byte.d;
            buffer += sizeof(cl_device_id);
            
            // Determine the size of the log
            size_t log_size;
            clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
            
            // Allocate memory for the log
            char *log = (char *) malloc(log_size);
            
            // Get the log
            err = clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
            
            // Return the log
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_GET_BUILD_LOG;
            response.data_len = sizeof(cl_int) + log_size;
            send_packet(response);
            send(send_client_socket, log, log_size, 0);
            printf("[CLIPClient]: Successfully processed request [getBuildLog]\n");
            free(log);
            break;
        case REQ_CL_CREATE_BUFFER:;
            buffer = (char *)request.data;
            
            i = 0;
            for (; i < sizeof(cl_context); i++) { reassemble_8byte.data[i] = buffer[i]; }
            context = reassemble_8byte.c;
            buffer += sizeof(cl_context);
            
            i = 0;
            for (; i < sizeof(cl_mem_flags); i++) { reassemble_8byte.data[i] = buffer[i]; }
            cl_mem_flags flags = reassemble_8byte.f;
            buffer += sizeof(cl_mem_flags);
            
            i = 0;
            for (; i < sizeof(size_t); i++) { reassemble_8byte.data[i] = buffer[i]; }
            size_t size = reassemble_8byte.s;
            buffer += sizeof(size_t);
            
            cl_mem mem = clCreateBuffer(context, flags, size, (void *)buffer, &err);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_CREATE_BUFFER;
            response.data_len = sizeof(cl_int) + sizeof(cl_mem);
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_int), 0);
            send(send_client_socket, &mem, sizeof(cl_mem), 0);
            printf("[CLIPClient]: Successfully processed request [createBuffer]\n");
            break;
        case REQ_CL_CREATE_KERNEL:;
            buffer = (char *)request.data;
            
            i = 0;
            for (; i < sizeof(cl_program); i++) { reassemble_8byte.data[i] = buffer[i]; }
            program = reassemble_8byte.p;
            buffer += sizeof(cl_program);
            
            kernel = clCreateKernel(program, buffer, &err);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_CREATE_KERNEL;
            response.data_len = sizeof(cl_int) + sizeof(cl_kernel);
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_int), 0);
            send(send_client_socket, &kernel, sizeof(cl_kernel), 0);
            printf("[CLIPClient]: Successfully processed request [createKernel]\n");
            break;
        case REQ_CL_SET_KERNEL_ARG:;
            buffer = (char *)request.data;
            
            i = 0;
            for (; i < sizeof(cl_kernel); i++) { reassemble_8byte.data[i] = buffer[i]; }
            kernel = reassemble_8byte.k;
            buffer += sizeof(cl_kernel);
            
            i = 0;
            for (; i < sizeof(cl_uint); i++) { reassemble_cluint.data[i] = buffer[i]; }
            cl_uint arg_pos = reassemble_cluint.u;
            buffer += sizeof(cl_uint);
            
            i = 0;
            for (; i < sizeof(size_t); i++) { reassemble_8byte.data[i] = buffer[i]; }
            size_t size_arg = reassemble_8byte.s;
            buffer += sizeof(size_t);
            
            err = clSetKernelArg(kernel, arg_pos, size_arg, (void *)buffer);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_SET_KERNEL_ARG;
            response.data_len = sizeof(cl_int);
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_uint), 0);
            printf("[CLIPClient]: Successfully processed request [setKernelArg]\n");
            break;
        case REQ_CL_ENQUEUE_ND_RANGE_KERNEL:;
            buffer = (char *)request.data;
            
            i = 0;
            for (; i < sizeof(cl_command_queue); i++) { reassemble_8byte.data[i] = buffer[i]; }
            queue = reassemble_8byte.q;
            buffer += sizeof(cl_command_queue);
            
            i = 0;
            for (; i < sizeof(cl_kernel); i++) { reassemble_8byte.data[i] = buffer[i]; }
            kernel = reassemble_8byte.k;
            buffer += sizeof(cl_kernel);
            
            i = 0;
            for (; i < sizeof(cl_uint); i++) { reassemble_cluint.data[i] = buffer[i]; }
            int work_dim = reassemble_cluint.u;
            buffer += sizeof(cl_uint);
            
            i = 0;
            for (; i < sizeof(size_t); i++) { reassemble_8byte.data[i] = buffer[i]; }
            size_t global = reassemble_8byte.s;
            buffer += sizeof(size_t);
            
            i = 0;
            for (; i < sizeof(size_t); i++) { reassemble_8byte.data[i] = buffer[i]; }
            size_t local = reassemble_8byte.s;

            printf("[CLIPClient]: Starting kernel...\n");
            fflush(stdout);
            
            err = clEnqueueNDRangeKernel(queue, kernel, work_dim, NULL, &global, &local, 0, NULL, NULL);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_ENQUEUE_ND_RANGE_KERNEL;
            response.data_len = sizeof(cl_int);
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_int), 0);
            printf("[CLIPClient]: Successfully processed request [enqueueNDRangeKernel]\n");
            break;
        case REQ_CL_FINISH:;
            buffer = (char *)request.data;
            
            i = 0;
            for (; i < sizeof(cl_command_queue); i++) { reassemble_8byte.data[i] = buffer[i]; }
            queue = reassemble_8byte.q;
            buffer += sizeof(cl_command_queue);
            
            clFinish(queue);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_FINISH;
            response.data_len = 0;
            send_packet(response);
            printf("[CLIPClient]: Successfully processed request [clFinish]\n");
            break;
        case REQ_CL_ENQUEUE_READ_BUFFER:;
            buffer = (char *)request.data;
            
            i = 0;
            for (; i < sizeof(cl_command_queue); i++) { reassemble_8byte.data[i] = buffer[i]; }
            queue = reassemble_8byte.q;
            buffer += sizeof(cl_command_queue);
            
            i = 0;
            for (; i < sizeof(cl_mem); i++) { reassemble_8byte.data[i] = buffer[i]; }
            cl_mem mem_obj = reassemble_8byte.m;
            buffer += sizeof(cl_mem);
            
            i = 0;
            for (; i < sizeof(size_t); i++) { reassemble_8byte.data[i] = buffer[i]; }
            size_t offset = reassemble_8byte.s;
            buffer += sizeof(size_t);
            
            i = 0;
            for (; i < sizeof(size_t); i++) { reassemble_8byte.data[i] = buffer[i]; }
            size_t cb = reassemble_8byte.s;
            
            void *ptr = malloc(cb);
            
            err = clEnqueueReadBuffer(queue, mem_obj, CL_TRUE, offset, cb, ptr, 0, NULL, NULL);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_ENQUEUE_READ_BUFFER;
            response.data_len = sizeof(cl_int) + cb;
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_int), 0);
            send(send_client_socket, ptr, cb, 0);
            printf("[CLIPClient]: Successfully processed request [clEnqueueReadBuffer]\n");
            free(ptr);
            break;
        case REQ_RELEASE_CLIENT:
            printf("[CLIPClient]: Server requested disconnect\n");
            shutdown(send_client_socket, 2);
            in_session = 0;
            break;
        case REQ_CL_RELEASE_MEM_OBJECT:;
            buffer = (char *)request.data;
            
            i = 0;
            for (; i < sizeof(cl_mem); i++) { reassemble_8byte.data[i] = buffer[i]; }
            cl_mem mem_rel = reassemble_8byte.m;
            buffer += sizeof(cl_mem);
            
            err = clReleaseMemObject(mem_rel);
            
            response.code = RSP_DIR_REQUEST;
            response.ext = REQ_CL_RELEASE_MEM_OBJECT;
            response.data_len = sizeof(cl_int);
            send_packet(response);
            send(send_client_socket, &err, sizeof(cl_int), 0);
            printf("[CLIPClient]: Successfully processed request [releaseMemObject]\n");
            break;
    }
}

int processing_mode()
{
    printf("[CLIPClient]: Connected/waiting for work\n");
    
    unsigned long recieved_size, required_size = 0, acquired_header = 0, count = 0, absposition = 0;
    struct CLIP_response_packet response;
    char inc_buffer[MAXDATASIZE];
    char *external_buffer = NULL;
    
    while (in_session)
    {
        recieved_size = recv(send_client_socket, inc_buffer, MAXDATASIZE, 0);
        if (recieved_size == -1) { in_session = 0; }
        if (recieved_size > 0)
        {
            count += recieved_size;
            if (acquired_header == 0)
            {
#pragma pack(1)
                union
                {
                    int prt[2];
                    char buf[8];
                } reassemble;
#pragma pack(0)
                int i = 0;
                for (; i < 8; i++) { reassemble.buf[i] = inc_buffer[i]; }
                response.code = reassemble.prt[0];
                response.ext  = reassemble.prt[1];
                i = 0;
                for (; i < 8; i++) { reassemble_8byte.data[i] = inc_buffer[i+8]; }
                response.data_len = reassemble_8byte.s;
                
                printf("[CLIPClient]: Got packet:\n\tCode:%i\n\tExt:%i\n\tD_Len:%zu\n", response.code, response.ext, response.data_len);
                
                required_size = response.data_len;
                acquired_header = 1;
                
                printf("DEBUG:\n\tRequired_SIZE:%lu\n\trec:%lu\n\tSizeofStruct:%lu\n", required_size, recieved_size, sizeof(response));
                
                if (response.data_len <= 0)
                {
                    acquired_header = 0;
                    required_size = 0;
                    count = 0;
                    process_request(response);
                    continue;
                }
                else
                {
                    count -= sizeof(response);
                    external_buffer = (char *)calloc(response.data_len, sizeof(char));
                    response.data = external_buffer;
                    int i = 0;
                    for (; i < (recieved_size-sizeof(response)); i++) { external_buffer[i] = inc_buffer[i+sizeof(response)]; }
                    absposition = i;
                    printf("MOREDEBUG:\n\tabspos:%lu\n\tcount:%lu", absposition, count);
                    if (absposition == required_size)
                    {
                        acquired_header = 0;
                        required_size = 0;
                        count = 0;
                        process_request(response);
                        free(external_buffer);
                    }
                    continue;
                }
            }
            if (count == required_size)
            {
                int i = 0;
                printf("==:\n\tabspos:%lu\n\tcount:%lu", absposition, count);
                for (; i < recieved_size; i++) { external_buffer[i+absposition] = inc_buffer[i]; }
                acquired_header = 0;
                required_size = 0;
                count = 0;
                process_request(response);
                free(external_buffer);
                continue;
            }
            else if (count < required_size)
            {
                int i = 0;
                for (; i < recieved_size; i++) { external_buffer[i+absposition] = inc_buffer[i]; }
                absposition += recieved_size;
                //printf("elseif:\n\tabspos:%lu\n\tcount:%lu", absposition, count);
            }
        }
    }
    
    return 0;
}

int main(void)
{
    printf(" ██████╗██╗     ██╗██████╗\n");
    printf("██╔════╝██║     ██║██╔══██╗\n");
    printf("██║     ██║     ██║██████╔╝\n");
    printf("██║     ██║     ██║██╔═══╝\n");
    printf("╚██████╗███████╗██║██║client\n");
    printf(" ╚═════╝╚══════╝╚═╝╚═╝\n");
    printf("CLIPClient 1: Remote GPGPU - Carter McCardwell, mccardwell.net\n");
    assert(enable_server());
    assert(hold_for_connection());
    while (1)
    {
        if (in_session == 1)
        {
            assert(processing_mode());
        }
        else
        {
            assert(hold_for_connection());
        }
    }
    
    return 0;
}