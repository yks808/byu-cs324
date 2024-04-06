#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <semaphore.h>

/* Recommended max object size */
#define MAX_OBJECT_SIZE 102400
#define BUFFER_SIZE 5
#define NUM_CONSUMER_THREADS 8

static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:97.0) Gecko/20100101 Firefox/97.0";

typedef struct
{
	int buffer[BUFFER_SIZE];
	sem_t empty;
	sem_t full;
	pthread_mutex_t mutex;
	int in;
	int out;
} Buffer;

Buffer shared_buffer;

int complete_request_received(char *);
int parse_request(char *, char *, char *, char *, char *);
void test_parser();
void print_bytes(unsigned char *, int);
int open_sfd(int port);
void handle_client(int client_fd);
void *thread_handle_client(void *client_fd);
void *consumer_thread(void *arg);

int main(int argc, char *argv[])
{

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <port>\n", argv[0]);
		return 1;
	}

	int port = atoi(argv[1]);
	int server_fd = open_sfd(port);

	pthread_t consumer_threads[NUM_CONSUMER_THREADS];

	sem_init(&shared_buffer.empty, 0, BUFFER_SIZE);
	sem_init(&shared_buffer.full, 0, 0);
	pthread_mutex_init(&shared_buffer.mutex, NULL);
	shared_buffer.in = 0;
	shared_buffer.out = 0;

	// create consumer threads
	for (int i = 0; i < NUM_CONSUMER_THREADS; ++i)
	{
		pthread_create(&consumer_threads[i], NULL, consumer_thread, NULL);
	}

	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t client_addr_len = sizeof(client_addr);

		// allocating memory for client_fd
		// int *client_fd = malloc(sizeof(int));
		int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);

		if (client_fd < 0)
		{
			perror("Error accepting connection");
			continue;
		}

		// pthread_t thread_id;
		// if (pthread_create(&thread_id, NULL, thread_handle_client, (void *)client_fd) != 0)
		// {
		// 	perror("Error creating thread");
		// 	close(*client_fd);
		// 	free(client_fd);
		// }
		// else
		// {
		// 	pthread_detach(thread_id);
		// }
		sem_wait(&shared_buffer.empty);
		pthread_mutex_lock(&shared_buffer.mutex);
		shared_buffer.buffer[shared_buffer.in] = client_fd;
		shared_buffer.in = (shared_buffer.in + 1) % BUFFER_SIZE;
		pthread_mutex_unlock(&shared_buffer.mutex);
		sem_post(&shared_buffer.full);
	}

	close(server_fd);

	return 0;
}

void *consumer_thread(void *arg)
{
	while (1)
	{
		// Remove client_fd from shared buffer
		sem_wait(&shared_buffer.full);
		pthread_mutex_lock(&shared_buffer.mutex);
		int client_fd = shared_buffer.buffer[shared_buffer.out];
		shared_buffer.out = (shared_buffer.out + 1) % BUFFER_SIZE;
		pthread_mutex_unlock(&shared_buffer.mutex);
		sem_post(&shared_buffer.empty);

		handle_client(client_fd);
		close(client_fd);
	}
	return NULL;
}
void *thread_handle_client(void *client_fd)
{
	int client_socket = *((int *)client_fd);
	free(client_fd);

	handle_client(client_socket);

	close(client_socket);
	pthread_exit(NULL);
}

int complete_request_received(char *request)
{
	return 0;
}

int parse_request(char *request, char *method, char *hostname, char *port, char *path)
{
	// Extract method
	char *end_of_method = strstr(request, " ");
	if (end_of_method != NULL)
	{
		strncpy(method, request, end_of_method - request);
		method[end_of_method - request] = '\0';
	}
	else
	{
		printf("Method failed\n");
		return 0;
	}

	// Extract URL
	char *start_of_url = strstr(request, "http://");
	if (start_of_url != NULL)
	{
		char *end_of_url = strstr(start_of_url, " ");
		if (end_of_url != NULL)
		{
			int url_length = end_of_url - start_of_url;
			//+ 1 for '0'
			char url[url_length + 1];
			strncpy(url, start_of_url, url_length);
			url[url_length] = '\0';

			// get hostname, port, and path from the URL
			// skip "http://"
			char *start_of_hostname = start_of_url + 7;
			char *end_of_hostname = strchr(start_of_hostname, ':');
			char *end_of_path = strchr(start_of_hostname, '/');

			if (end_of_hostname != NULL && (end_of_path == NULL || end_of_path > end_of_hostname))
			{
				int hostname_length = end_of_hostname - start_of_hostname;
				strncpy(hostname, start_of_hostname, hostname_length);
				hostname[hostname_length] = '\0';

				int port_length;
				if (end_of_path != NULL)
				{
					port_length = end_of_path - end_of_hostname - 1;
				}
				else
				{
					port_length = start_of_url + url_length - end_of_hostname - 1;
				}

				strncpy(port, end_of_hostname + 1, port_length);
				port[port_length] = '\0';
			}
			else
			{
				strcpy(port, "80");
				int hostname_length;
				if (end_of_path != NULL)
				{
					hostname_length = end_of_path - start_of_hostname;
				}
				else
				{
					hostname_length = start_of_url + url_length - start_of_hostname;
				}
				strncpy(hostname, start_of_hostname, hostname_length);
				hostname[hostname_length] = '\0';
			}

			if (end_of_path != NULL)
			{
				int path_length = start_of_url + url_length - end_of_path;
				strncpy(path, end_of_path, path_length);
				path[path_length] = '\0';
			}
			else
			{
				printf("Path extraction failed\n");
				return 0;
			}
			return 1;
		}
		else
		{
			printf("URL failed\n");
			return 0;
		}
	}
	else
	{
		printf("URL cannot find\n");
		return 0;
	}
}

void test_parser()
{
	int i;
	char method[16], hostname[64], port[8], path[64];

	char *reqs[] = {
		"GET http://www.example.com/index.html HTTP/1.0\r\n"
		"Host: www.example.com\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html?foo=1&bar=2 HTTP/1.0\r\n"
		"Host: www.example.com:8080\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://localhost:1234/home.html HTTP/1.0\r\n"
		"Host: localhost:1234\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html HTTP/1.0\r\n",

		NULL};

	for (i = 0; reqs[i] != NULL; i++)
	{
		printf("Testing %s\n", reqs[i]);
		if (parse_request(reqs[i], method, hostname, port, path))
		{
			printf("Method: %s, Hostname: %s, Port: %s, Path: %s\n", method, hostname, port, path);
		}
		else
		{
			printf("REQUEST INCOMPLETE\n");
		}
	}
}

void print_bytes(unsigned char *bytes, int byteslen)
{
	int i, j, byteslen_adjusted;

	if (byteslen % 8)
	{
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	}
	else
	{
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++)
	{
		if (!(i % 8))
		{
			if (i > 0)
			{
				for (j = i - 8; j < i; j++)
				{
					if (j >= byteslen_adjusted)
					{
						printf("  ");
					}
					else if (j >= byteslen)
					{
						printf("  ");
					}
					else if (bytes[j] >= '!' && bytes[j] <= '~')
					{
						printf(" %c", bytes[j]);
					}
					else
					{
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted)
			{
				printf("\n%02X: ", i);
			}
		}
		else if (!(i % 4))
		{
			printf(" ");
		}
		if (i >= byteslen_adjusted)
		{
			continue;
		}
		else if (i >= byteslen)
		{
			printf("   ");
		}
		else
		{
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

int open_sfd(int port)
{
	int server_fd;
	struct sockaddr_in addr;
	int optval = 1;

	// create socket
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
	{
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	// allow to immediately restart your HTTP proxy after failure, rather than having to wait for it to time out.
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) == -1)
	{
		perror("Setsockopt failed");
		exit(EXIT_FAILURE);
	}

	// bind socket to port
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

	// listen for incoming connections
	if (listen(server_fd, 5) < 0)
	{
		perror("Listen failed");
		exit(EXIT_FAILURE);
	}

	return server_fd;
}

void handle_client(int client_fd)
{
	char request[1024] = {0};
	ssize_t bytes_read;
	size_t total_bytes_read = 0;

	// Read request from client
	while ((bytes_read = read(client_fd, request + total_bytes_read, 1024 - total_bytes_read)) > 0)
	{
		total_bytes_read += bytes_read;

		// check to see if end of request headers reached
		if (strstr(request, "\r\n\r\n") != NULL)
		{
			break;
		}
	}

	if (bytes_read == -1)
	{
		perror("Error reading from client");
		return;
	}

	// print the HTTP request
	printf("HTTP Request:\n");
	print_bytes((unsigned char *)request, strlen(request));

	// null-terminate the request
	request[total_bytes_read] = '\0';

	// parse the request
	char method[16], hostname[64], port_str[8], path[64];
	if (!parse_request(request, method, hostname, port_str, path))
	{
		printf("Failed to parse request\n");
		return;
	}

	char new_request[1024];

	snprintf(new_request, 1024, "%s %s HTTP/1.0\r\nHost: %s:%s\r\nUser-Agent: %s\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n",
			 method, path, hostname, port_str, user_agent_hdr);

	// Print the modified HTTP request
	printf("Modified HTTP Request:\n");
	print_bytes((unsigned char *)new_request, strlen(new_request));

	int server_fd = -1;

	struct addrinfo hints, *server_info = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int status = getaddrinfo(hostname, port_str, &hints, &server_info);
	if (status != 0)
	{
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		return;
	}

	struct addrinfo *p;
	for (p = server_info; p != NULL; p = p->ai_next)
	{

		server_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (server_fd == -1)
		{
			perror("Socket creation error");
			continue;
		}

		if (connect(server_fd, p->ai_addr, p->ai_addrlen) == -1)
		{
			close(server_fd);
			perror("Connect failed");
			continue;
		}
		// successfully connected
		break;
	}

	if (server_fd == -1)
	{
		perror("Failed to connect to server");
		return;
	}

	// send modified request to the server
	printf("hello before sending\n");
	ssize_t bytes_sent = send(server_fd, new_request, strlen(new_request), 0);
	if (bytes_sent < 0)
	{
		perror("Error sending request to server");
		close(server_fd);
		return;
	}
	char response_buffer[1024];
	ssize_t bytes_received;

	printf("HTTP Response:\n");

	while ((bytes_received = recv(server_fd, response_buffer, sizeof(response_buffer), 0)) > 0)
	{
		print_bytes((unsigned char *)response_buffer, bytes_received);

		// send recieve back to the client
		ssize_t bytes_written = write(client_fd, response_buffer, bytes_received);
		if (bytes_written < 0)
		{
			perror("Error writing response to client");
			break;
		}
	}

	if (bytes_received == -1)
	{
		perror("Error receiving response from server");
	}

	close(server_fd);
	freeaddrinfo(server_info);
	close(client_fd);
}
