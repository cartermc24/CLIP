//
//  CLIPFramework.c
//  CLIPFramework
//
//  Created by Carter McCardwell on 1/15/16.
//  Copyright © 2016 Carter McCardwell. All rights reserved.
//

#include "CLIPFramework.h"
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

//Status codes
#define DISCONNECTED 30
#define DISCONNECTED_ERR 31
#define PENDING 32 //Waiting for handshake to be recieved
#define CONNECTED 33
//End status codes

//Connection parameters
#define PORT "4889" //The port is hard-coded for now
#define MAXDATASIZE 1000 // max number of bytes that can be obtained
#define TIMEOUT 10000 //Timeout for requests
#define TIMEOUT_STEP 10000 //TIMEOUT*TIMEOUT_STEP = Total Delay
//End connection parameters

//Other parameters
#define MAX_HOST_SIZE 100 //Max number of charactors per hostname in hostfile
#define MAX_HOSTS 25 //Maximum number of hosts that can be connected to
//End other parameters

//Required includes
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <OpenCL/OpenCL.h>
//End required includes

//Structs
#pragma pack(1)
struct CLIP_response_packet
{
    int code;
    int ext;
    size_t data_len;
    void *data;
};
#pragma pack(0)
//End structs

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
    cl_mem m;
    cl_kernel k;
    cl_program p;
    cl_context c;
    cl_device_id d;
    cl_platform_id pl;
    cl_command_queue cq;
    size_t s;
} reassemble_8byte;
#pragma pack(0)
//End standard unions

//Globals
int num_hosts;
int bind_host_socket;
int silent;
pthread_t listener_thread;
pthread_t connection_agent_thread[MAX_HOSTS];
struct connection connections[MAX_HOSTS];
struct CLIP_response_packet dir_response = {-1, -1, 0, NULL};
//End globals

void reset_response()
{
    dir_response.code = -1;
    dir_response.ext = -1;
    dir_response.data_len = 0;
    free(dir_response.data);
    dir_response.data = NULL;
}

void assert(int e)
{
    switch (e)
    {
        case -1:
            fprintf(stderr, "[CLIP]: Fatal error, terminating\n");
            exit(1);
            break;
    }
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    
    while(waitpid(-1, NULL, WNOHANG) > 0);
    
    errno = saved_errno;
}

void process_response(struct CLIP_response_packet response, int id)
{
    switch (response.code)
    {
        case HANDSHAKE:
            printf("[CLIP]: Connection confirmed for host [%s]\n", connections[id].host);
            connections[id].status = CONNECTED;
            break;
        case DATA_CONTAINED:
            printf("[CLIP]: Starting data transfer from remote host [%s]\n", connections[id].host);
            printf("[CLIP]: Response [%s]\n", (char *)response.data);
            break;
        case RSP_DIR_REQUEST:
            printf("[CLIP]: Response from host [%s] recieved\n", connections[id].host);
            dir_response = response;
            break;
        default:
            printf("[CLIP]: Unknown response from host [%s] : code:%i\n", connections[id].host, response.code);
            break;
    }
}

void *connection_agent(void *i_d)
{
    int id = (*((int *)i_d) - 1);
    printf("[CLIP]: Starting connection manager [%i]\n", id);
    
    unsigned long recieved_size, required_size = 0, acquired_header = 0, count = 0, absposition = 0;
    struct CLIP_response_packet response;
    char inc_buffer[MAXDATASIZE];
    char *external_buffer = NULL;
    
    while (1)
    {
        recieved_size = recv(connections[id].reciv_socket, inc_buffer, MAXDATASIZE, 0);
        if (recieved_size == -1)
        {
            connections[id].status = DISCONNECTED_ERR;
            fprintf(stderr, "[CLIP]: Error, host [%s] was disconnected\n", connections[id].host);
            return NULL;
        }
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
                    process_response(response, id);
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
                        process_response(response, id);
                        //free(external_buffer);
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
                process_response(response, id);
                //free(external_buffer);
                continue;
            }
            else if (count < required_size)
            {
                int i = 0;
                for (; i < recieved_size; i++) { external_buffer[i+absposition] = inc_buffer[i]; }
                absposition += recieved_size;
                printf("elseif:\n\tabspos:%lu\n\tcount:%lu", absposition, count);
            }
        }
    }
    
    return 0;
}

int establish_sock(char* host, int *sockid)
{
    int sock_id = 0, err;
    struct addrinfo srt, *service_info, *current;
    char addr[INET6_ADDRSTRLEN];
    
    memset(&srt, 0, sizeof(srt));
    srt.ai_family = AF_UNSPEC; //Unspecified IPv type
    srt.ai_socktype = SOCK_STREAM; //Use TCP
    
    if ((err = getaddrinfo(host, PORT, &srt, &service_info)) != 0) //If host can be derived
    {
        fprintf(stderr, "[CLIP]: Error identifing host %s / [%s]\n", host, gai_strerror(err));
        return -2;
    }
    
    //Find first valid connection
    for (current = service_info; current != NULL; current = current->ai_next)
    {
        if ((sock_id = socket(current->ai_family, current->ai_socktype, current->ai_protocol)) == -1)
        {
            continue;
        }
        if (connect(sock_id, current->ai_addr, current->ai_addrlen) == -1)
        {
            close(sock_id);
            continue;
        }
        break;
    }
    
    if (current == NULL) //If no connection was established, linked list reaches null
    {
        fprintf(stderr, "[CLIP]: Failed to connect to host %s\n", host);
        return -2;
    }
    
    inet_ntop(current->ai_family, get_in_addr((struct sockaddr *)current->ai_addr), addr, sizeof addr);
    printf("[CLIP]: Connected to [%s] (%s)\n", host, addr); //Print IP address of connected host
    freeaddrinfo(service_info); //Free host asset linked list
    *sockid = sock_id;
    return 0;
}

int file_to_hostnames(char* filename, char hosts[MAX_HOSTS][MAX_HOST_SIZE], int *num_hosts)
{
    FILE *hostfile;
    hostfile = fopen(filename, "r");
    if (hostfile == NULL)
    {
        fprintf(stderr, "[CLIP]: Cannot open hostfile\n");
        return -1;
    }
    
    memset(hosts, 0, sizeof(char)*MAX_HOST_SIZE*MAX_HOSTS);
    *num_hosts = 0;
    
    while (1)
    {
        if (fgets(hosts[*num_hosts], MAX_HOST_SIZE, hostfile) == NULL) { break; }
        (*num_hosts)++;
    }
    
    printf("[CLIP]: Target Hosts:\n");
    for (int i = 0; i < *num_hosts; i++)
    {
        hosts[i][strcspn(hosts[i], "\n")] = 0;
        printf("\t%i: %s\n", i, hosts[i]);
    }
    return 0;
}

//Most user accessable functions included below:

int init_clip(char* hostfile, int a_silent, int *num_hosts, struct connection **connection_str)
{
    printf("CLIPFramework b832: GPGPU over IP - Carter McCardwell, mccardwell.net\n[CLIP]: Starting...\n");
    silent = a_silent;
    
    //Get hosts from file
    char hosts[MAX_HOSTS][MAX_HOST_SIZE];
    assert(file_to_hostnames(hostfile, hosts, num_hosts));
    //End get hosts from file
    
    //Establish connections to hosts
    for (int i = 0; i < *num_hosts; i++)
    {
        connections[i].id = i;
        connections[i].host = hosts[i];
        int stat = establish_sock(hosts[i], &(connections[i].reciv_socket));
        if (stat != -2)
        {
            connections[i].status = PENDING;
            pthread_create(&connection_agent_thread[i], NULL, connection_agent, &i);
        }
        else { connections[i].status = DISCONNECTED_ERR; }
    }
    
    *connection_str = connections;
    
    usleep(1); //Allow manager to startup
    
    //End establish connections to hosts
    return 0;
}

cl_int clipGetPlatformIDs(int connection_id, cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms)
{
    printf("[CLIP]: Processing request [getPlatformIDs] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_GET_PLATFORM_ID;
    request.ext = (int)num_entries;
    request.data_len = 0;
    send(connections[connection_id].reciv_socket, &request, sizeof(request), 0);
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_GET_PLATFORM_ID)
        {
            const int response_size = 16; //Size of response to GetPlatformIDs [HC]
            if (response_size != dir_response.data_len)
            {
                fprintf(stderr, "[CLIP]: Response for request [getPlatformIDs] on host [%s] was invalid, ignoring\n", connections[connection_id].host);
                return -2;
            }
            cl_int ret;
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            ret = reassemble_clint.u;
            
            reassemble_8byte.data[0] = buffer[4];
            reassemble_8byte.data[1] = buffer[5];
            reassemble_8byte.data[2] = buffer[6];
            reassemble_8byte.data[3] = buffer[7];
            reassemble_8byte.data[4] = buffer[8];
            reassemble_8byte.data[5] = buffer[9];
            reassemble_8byte.data[6] = buffer[10];
            reassemble_8byte.data[7] = buffer[11];
            *platforms = reassemble_8byte.pl;
            
            reassemble_cluint.data[0] = buffer[12];
            reassemble_cluint.data[1] = buffer[13];
            reassemble_cluint.data[2] = buffer[14];
            reassemble_cluint.data[3] = buffer[15];
            *num_platforms = reassemble_cluint.u;
            reset_response();
            return ret;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [getPlatformIDs] on host [%s]", connections[connection_id].host);
    return -2;
}


cl_int clipGetDeviceIDs(int connection_id, cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices)
{
    printf("[CLIP]: Processing request [getDeviceIDs] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_GET_DEVICE_ID;
    request.ext = -1;
    request.data_len = sizeof(cl_platform_id)+sizeof(cl_device_type)+sizeof(cl_uint);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &platform, sizeof(cl_platform_id), 0);
    send(connections[connection_id].reciv_socket, &device_type, sizeof(cl_device_type), 0);
    send(connections[connection_id].reciv_socket, &num_entries, sizeof(cl_uint), 0);
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_GET_DEVICE_ID)
        {
            cl_int ret;
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            ret = reassemble_clint.u;
            
            reassemble_cluint.data[0] = buffer[4];
            reassemble_cluint.data[1] = buffer[5];
            reassemble_cluint.data[2] = buffer[6];
            reassemble_cluint.data[3] = buffer[7];
            *num_devices = reassemble_cluint.u;
            
            for (int i = 0; i < *num_devices; i++)
            {
                reassemble_8byte.data[0] = buffer[8+(8*i)];
                reassemble_8byte.data[1] = buffer[9+(8*i)];
                reassemble_8byte.data[2] = buffer[10+(8*i)];
                reassemble_8byte.data[3] = buffer[11+(8*i)];
                reassemble_8byte.data[4] = buffer[12+(8*i)];
                reassemble_8byte.data[5] = buffer[13+(8*i)];
                reassemble_8byte.data[6] = buffer[14+(8*i)];
                reassemble_8byte.data[7] = buffer[15+(8*i)];
                devices[i] = reassemble_8byte.d;
            }

            reset_response();
            return ret;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [getDeviceIDs] on host [%s]", connections[connection_id].host);
    return -2;
}

cl_context clipCreateContext(int connection_id, cl_uint num_devices, cl_device_id *devices, cl_int *err)
{
    printf("[CLIP]: Processing request [createContext] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_CREATE_CONTEXT;
    request.ext = num_devices;
    request.data_len = num_devices*sizeof(cl_device_id);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    for (int i = 0; i < num_devices; i++)
    {
        send(connections[connection_id].reciv_socket, (devices+i), sizeof(cl_platform_id), 0);
    }
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_CREATE_CONTEXT)
        {
            const int response_size = 12; //Size of response [HC]
            if (response_size != dir_response.data_len)
            {
                fprintf(stderr, "[CLIP]: Response for request [createContext] on host [%s] was invalid, ignoring\n", connections[connection_id].host);
                *err = -2;
                return NULL;
            }
            cl_context context;
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            *err = reassemble_clint.u;
            
            reassemble_8byte.data[0] = buffer[4];
            reassemble_8byte.data[1] = buffer[5];
            reassemble_8byte.data[2] = buffer[6];
            reassemble_8byte.data[3] = buffer[7];
            reassemble_8byte.data[4] = buffer[8];
            reassemble_8byte.data[5] = buffer[9];
            reassemble_8byte.data[6] = buffer[10];
            reassemble_8byte.data[7] = buffer[11];
            context = reassemble_8byte.c;
            
            reset_response();
            return context;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [createContext] on host [%s]", connections[connection_id].host);
    return NULL;
}

cl_command_queue clipCreateCommandQueue(int connection_id, cl_context context, cl_device_id device, cl_int *err)
{
    printf("[CLIP]: Processing request [createCommandQueue] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_CREATE_COMMAND_QUEUE;
    request.ext = -1;
    request.data_len = sizeof(cl_device_id) + sizeof(cl_context);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &context, sizeof(cl_context), 0);
    send(connections[connection_id].reciv_socket, &device, sizeof(cl_device_id), 0);
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_CREATE_COMMAND_QUEUE)
        {
            const int response_size = 12; //Size of response [HC]
            if (response_size != dir_response.data_len)
            {
                fprintf(stderr, "[CLIP]: Response for request [createCommandQueue] on host [%s] was invalid, ignoring\n", connections[connection_id].host);
                *err = -2;
                return NULL;
            }
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            *err = reassemble_clint.u;
            
            reassemble_8byte.data[0] = buffer[4];
            reassemble_8byte.data[1] = buffer[5];
            reassemble_8byte.data[2] = buffer[6];
            reassemble_8byte.data[3] = buffer[7];
            reassemble_8byte.data[4] = buffer[8];
            reassemble_8byte.data[5] = buffer[9];
            reassemble_8byte.data[6] = buffer[10];
            reassemble_8byte.data[7] = buffer[11];
            cl_command_queue queue = reassemble_8byte.cq;
            
            reset_response();
            return queue;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [createCommandQueue] on host [%s]", connections[connection_id].host);
    return NULL;
}

cl_program clipCreateProgramWithSource(int connection_id, cl_context context, char *src_str, cl_int *err)
{
    printf("[CLIP]: Processing request [createProgramWithSource] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_CREATE_PROGRAM_SRC;
    request.ext = -1;
    request.data_len = strlen(src_str) + sizeof(cl_context);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &context, sizeof(cl_context), 0);
    send(connections[connection_id].reciv_socket, src_str, strlen(src_str), 0);
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_CREATE_PROGRAM_SRC)
        {
            const int response_size = 12; //Size of response [HC]
            if (response_size != dir_response.data_len)
            {
                fprintf(stderr, "[CLIP]: Response for request [createProgramWithSource] on host [%s] was invalid, ignoring\n", connections[connection_id].host);
                *err = -2;
                return NULL;
            }
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            *err = reassemble_clint.u;
            
            reassemble_8byte.data[0] = buffer[4];
            reassemble_8byte.data[1] = buffer[5];
            reassemble_8byte.data[2] = buffer[6];
            reassemble_8byte.data[3] = buffer[7];
            reassemble_8byte.data[4] = buffer[8];
            reassemble_8byte.data[5] = buffer[9];
            reassemble_8byte.data[6] = buffer[10];
            reassemble_8byte.data[7] = buffer[11];
            cl_program program = reassemble_8byte.p;
            
            reset_response();
            return program;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [createProgramWithSource] on host [%s]", connections[connection_id].host);
    return NULL;
}

cl_int clipBuildProgram(int connection_id, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options)
{
    printf("[CLIP]: Processing request [buildProgram] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_BUILD_PROGRAM;
    request.ext = -1;
    request.data_len = sizeof(cl_program) + sizeof(cl_uint) + num_devices*sizeof(cl_device_id);
    if (options != NULL) { request.data_len += strlen(options); }
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &program, sizeof(cl_program), 0);
    send(connections[connection_id].reciv_socket, &num_devices, sizeof(cl_uint), 0);
    for (int i = 0; i < num_devices; i++)
    {
        send(connections[connection_id].reciv_socket, (device_list+i), sizeof(cl_platform_id), 0);
    }
    if (options != NULL) { send(connections[connection_id].reciv_socket, options, strlen(options), 0); }
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_BUILD_PROGRAM)
        {
            const int response_size = sizeof(cl_int); //Size of response [HC]
            if (response_size != dir_response.data_len)
            {
                fprintf(stderr, "[CLIP]: Response for request [buildProgram] on host [%s] was invalid, ignoring\n", connections[connection_id].host);
                return -2;
            }
            
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            reset_response();
            return reassemble_clint.u;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [buildProgram] on host [%s]", connections[connection_id].host);
    return -2;
}

cl_int clipGetBuildLog(int connection_id, cl_program program, cl_device_id device, char **log)
{
    printf("[CLIP]: Processing request [getBuildLog] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_GET_BUILD_LOG;
    request.ext = -1;
    request.data_len = sizeof(cl_program) + sizeof(cl_device_id);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &program, sizeof(cl_program), 0);
    send(connections[connection_id].reciv_socket, &device, sizeof(cl_device_id), 0);
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_GET_BUILD_LOG)
        {            
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            buffer += sizeof(cl_int);
            
            *log = (char *)calloc(strlen(buffer), sizeof(char));
            int res = memcpy(*log, buffer, strlen(buffer)*sizeof(char));

            reset_response();
            return reassemble_clint.u;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [getBuildLog] on host [%s]", connections[connection_id].host);
    return -2;
}

cl_mem clipCreateBuffer(int connection_id, cl_context context, cl_mem_flags flags, size_t size, void *host_ptr, cl_int *errcode_ret)
{
    printf("[CLIP]: Processing request [createBuffer] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_CREATE_BUFFER;
    request.ext = -1;
    request.data_len = sizeof(cl_context) + sizeof(cl_mem_flags) + sizeof(size_t) + size;
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &context, sizeof(cl_context), 0);
    send(connections[connection_id].reciv_socket, &flags, sizeof(cl_mem_flags), 0);
    send(connections[connection_id].reciv_socket, &size, sizeof(size_t), 0);
    send(connections[connection_id].reciv_socket, host_ptr, size, 0);
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_CREATE_BUFFER)
        {
            const int response_size = sizeof(cl_mem) + sizeof(cl_int); //Size of response [HC]
            if (response_size != dir_response.data_len)
            {
                fprintf(stderr, "[CLIP]: Response for request [createBuffer] on host [%s] was invalid, ignoring\n", connections[connection_id].host);
                *errcode_ret = -2;
                return NULL;
            }
            
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            *errcode_ret = reassemble_clint.u;
            
            reassemble_8byte.data[0] = buffer[4];
            reassemble_8byte.data[1] = buffer[5];
            reassemble_8byte.data[2] = buffer[6];
            reassemble_8byte.data[3] = buffer[7];
            reassemble_8byte.data[4] = buffer[8];
            reassemble_8byte.data[5] = buffer[9];
            reassemble_8byte.data[6] = buffer[10];
            reassemble_8byte.data[7] = buffer[11];
            cl_mem mem = reassemble_8byte.m;
            
            reset_response();
            return mem;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [createBuffer] on host [%s]", connections[connection_id].host);
    *errcode_ret = -2;
    return NULL;
}

cl_kernel clipCreateKernel(int connection_id, cl_program program, const char *kernel_name, cl_int *errcode_ret)
{
    printf("[CLIP]: Processing request [createKernel] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_CREATE_KERNEL;
    request.ext = -1;
    request.data_len = sizeof(cl_program) + strlen(kernel_name);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &program, sizeof(cl_program), 0);
    send(connections[connection_id].reciv_socket, kernel_name, strlen(kernel_name), 0);
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_CREATE_KERNEL)
        {
            const int response_size = sizeof(cl_mem) + sizeof(cl_int); //Size of response [HC]
            if (response_size != dir_response.data_len)
            {
                fprintf(stderr, "[CLIP]: Response for request [createKernel] on host [%s] was invalid, ignoring\n", connections[connection_id].host);
                *errcode_ret = -2;
                return NULL;
            }
            
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            *errcode_ret = reassemble_clint.u;
            
            reassemble_8byte.data[0] = buffer[4];
            reassemble_8byte.data[1] = buffer[5];
            reassemble_8byte.data[2] = buffer[6];
            reassemble_8byte.data[3] = buffer[7];
            reassemble_8byte.data[4] = buffer[8];
            reassemble_8byte.data[5] = buffer[9];
            reassemble_8byte.data[6] = buffer[10];
            reassemble_8byte.data[7] = buffer[11];
            cl_kernel kernel = reassemble_8byte.k;
            
            reset_response();
            return kernel;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [createKernel] on host [%s]", connections[connection_id].host);
    *errcode_ret = -2;
    return NULL;
}

cl_int clipSetKernelArg(int connection_id, cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value)
{
    printf("[CLIP]: Processing request [setKernelArg] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_SET_KERNEL_ARG;
    request.ext = -1;
    request.data_len = sizeof(cl_kernel) + sizeof(cl_uint) + sizeof(size_t) + arg_size;
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &kernel, sizeof(cl_kernel), 0);
    send(connections[connection_id].reciv_socket, &arg_index, sizeof(cl_uint), 0);
    send(connections[connection_id].reciv_socket, &arg_size, sizeof(size_t), 0);
    send(connections[connection_id].reciv_socket, arg_value, arg_size, 0);
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_SET_KERNEL_ARG)
        {
            const int response_size = sizeof(cl_int); //Size of response [HC]
            if (response_size != dir_response.data_len)
            {
                fprintf(stderr, "[CLIP]: Response for request [setKernelArg] on host [%s] was invalid, ignoring\n", connections[connection_id].host);
                return -2;
            }
            
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            int err_value = reassemble_clint.u;
            
            reset_response();
            return err_value;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [setKernelArg] on host [%s]", connections[connection_id].host);
    return -2;
}

cl_int clipEnqueueNDRangeKernel(int connection_id, cl_command_queue queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_size, const size_t *local_work_size)
{
    printf("[CLIP]: Processing request [enqueueNDRangeKernel] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_ENQUEUE_ND_RANGE_KERNEL;
    request.ext = -1;
    request.data_len = sizeof(cl_command_queue) + sizeof(cl_kernel) + sizeof(cl_uint) + 2*sizeof(size_t);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &queue, sizeof(cl_command_queue), 0);
    send(connections[connection_id].reciv_socket, &kernel, sizeof(cl_kernel), 0);
    send(connections[connection_id].reciv_socket, &work_dim, sizeof(cl_uint), 0);
    send(connections[connection_id].reciv_socket, global_work_size, sizeof(size_t), 0);
    send(connections[connection_id].reciv_socket, local_work_size, sizeof(size_t), 0);
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_ENQUEUE_ND_RANGE_KERNEL)
        {
            const int response_size = sizeof(cl_int); //Size of response [HC]
            if (response_size != dir_response.data_len)
            {
                fprintf(stderr, "[CLIP]: Response for request [enqueueNDRangeKernel] on host [%s] was invalid, ignoring\n", connections[connection_id].host);
                return -2;
            }
            
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            int err_value = reassemble_clint.u;
            
            reset_response();
            return err_value;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [enqueueNDRangeKernel] on host [%s]", connections[connection_id].host);
    return -2;
}

void clipFinish(int connection_id, cl_command_queue queue, int max_wait_cycles)
{
    printf("[CLIP]: Processing request [finish] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_FINISH;
    request.ext = -1;
    request.data_len = sizeof(cl_command_queue);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &queue, sizeof(cl_command_queue), 0);
    
    for (int i = 0; i < (max_wait_cycles+1); i++)
    {
        if (max_wait_cycles == 0) { i = -1; }
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_FINISH)
        {
            return;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [finish] on host [%s]", connections[connection_id].host);
}

cl_int clipEnqueueReadBuffer(int connection_id, cl_command_queue queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t cb, void *ptr)
{
    printf("[CLIP]: Processing request [enqueueNDRangeKernel] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_ENQUEUE_READ_BUFFER;
    request.ext = -1;
    request.data_len = sizeof(cl_command_queue) + sizeof(cl_mem) + 2*sizeof(size_t);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &queue, sizeof(cl_command_queue), 0);
    send(connections[connection_id].reciv_socket, &buffer, sizeof(cl_mem), 0);
    send(connections[connection_id].reciv_socket, &offset, sizeof(size_t), 0);
    send(connections[connection_id].reciv_socket, &cb, sizeof(size_t), 0);
    
    
    if (blocking_read == true) { if (fork() != 0) { return 0; } }
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_ENQUEUE_READ_BUFFER)
        {
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            int err_value = reassemble_clint.u;
            buffer += sizeof(cl_int);
        
            memcpy(ptr, buffer, cb);
        
            reset_response();
            return err_value;
        }
    }
    fprintf(stderr, "[CLIP]: Timeout in operation [enqueueReadBuffer] on host [%s]", connections[connection_id].host);
    return -2;
}

int clipReleaseClient(int connection_id)
{
    printf("[CLIP]: Releasing host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_RELEASE_CLIENT;
    request.ext = -1;
    request.data_len = 0;
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    connections[connection_id].status = DISCONNECTED;
    printf("[CLIP]: Host [%s] disconnected\n", connections[connection_id].host);
    return 0;
}

cl_int clipReleaseMemObject(int connection_id, cl_mem mem)
{
    printf("[CLIP]: Processing request [releaseMemObject] on host [%s]\n", connections[connection_id].host);
    struct CLIP_response_packet request;
    request.code = REQ_CL_RELEASE_MEM_OBJECT;
    request.ext = -1;
    request.data_len = sizeof(cl_mem);
    send(connections[connection_id].reciv_socket, &request, sizeof(struct CLIP_response_packet), 0);
    send(connections[connection_id].reciv_socket, &mem, sizeof(cl_mem), 0);
    
    for (int i = 0; i < TIMEOUT; i++)
    {
        usleep(TIMEOUT_STEP);
        if (dir_response.ext == REQ_CL_RELEASE_MEM_OBJECT)
        {
            char *buffer = (char *)dir_response.data;
            reassemble_clint.data[0] = buffer[0];
            reassemble_clint.data[1] = buffer[1];
            reassemble_clint.data[2] = buffer[2];
            reassemble_clint.data[3] = buffer[3];
            cl_int err_value = reassemble_clint.u;
            
            reset_response();
            return err_value;
        }
    }

    fprintf(stderr, "[CLIP]: Timeout in operation [releaseMemObject] on host [%s]", connections[connection_id].host);
    return -2;
}