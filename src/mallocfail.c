/*
https://stackoverflow.com/questions/1711170/unit-testing-for-failed-malloc

I saw a cool solution to this problem which was presented to me by S.
Paavolainen. The idea is to override the standard malloc(), which you can do
just in the linker, by a custom allocator which

 1. reads the current execution stack of the thread calling malloc()
 2. checks if the stack exists in a database that is stored on hard disk
    1. if the stack does not exist, adds the stack to the database and returns NULL
    2. if the stack did exist already, allocates memory normally and returns

Then you just run your unit test many times---this system automatically
enumerates through different control paths to malloc() failure and is much more
efficient and reliable than e.g. random testing.

*/

#define uthash_malloc libc_malloc

#include "uthash.h"
#include "xxh3.h"

#include <stdio.h>
#include <string.h>
#include <execinfo.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <unistd.h>
#include <backtrace.h>

#define HASH_BITS 64
#define HASH_BYTES ((HASH_BITS)/8)
#define HASH_HEX_BYTES ((HASH_BITS)/4)

extern void *(*libc_malloc)(size_t);
extern void *(*libc_calloc)(size_t, size_t);
extern void *(*libc_realloc)(void *, size_t);

struct traces_s {
	UT_hash_handle hh;
	char hash[HASH_HEX_BYTES+1];
};

static struct traces_s *traces = NULL;
static struct backtrace_state *state = NULL;
static char strbuf[1024];
static char *hashfile = NULL;
static char hashfile_default[] = "mallocfail_hashes";
static int debug = -1;
static int backtrace_count;
static int fail_count = 0;
static int max_fail_count = -1;


static void hex_encode(const unsigned char *in, unsigned int in_len, char *encoded)
{
	int i;
	for(i=0; i<in_len; i++){
		sprintf(&encoded[i*2], "%02x", in[i]);
	}
}


static int append_stack_context(const char *filename, const char *hash_str)
{
	FILE *fptr;

	struct traces_s *t = libc_malloc(sizeof(struct traces_s));
	memcpy(t->hash, hash_str, HASH_HEX_BYTES);
	t->hash[HASH_HEX_BYTES] = '\0';
	HASH_ADD_STR(traces, hash, t);

	fptr = fopen(filename, "at");
	if(!fptr){
		return 1;
	}
	fprintf(fptr, "%s\n", hash_str);

	fclose(fptr);
	return 0;
}


static void load_traces(const char *filename)
{
	FILE *fptr;
	char buf[1024];

	fptr = fopen(filename, "rt");
	if(!fptr){
		return;
	}

	while(!feof(fptr)){
		if(fgets(buf, 1024, fptr)){
			if(buf[strlen(buf)-1] == '\n'){
				buf[strlen(buf)-1] = '\0';

				struct traces_s *t = libc_malloc(sizeof(struct traces_s));
				memcpy(t->hash, buf, HASH_HEX_BYTES);
				t->hash[HASH_HEX_BYTES] = '\0';
				HASH_ADD_STR(traces, hash, t);
			}
		}
	}
	fclose(fptr);
}


static int stack_context_exists(const char *filename, const char *hash_str)
{
	struct traces_s *found_trace;
	int rc;

	if(traces == NULL){
		load_traces(filename);
	}

	HASH_FIND_STR(traces, hash_str, found_trace);
	if(found_trace){
		rc = 1;
	}else{
		append_stack_context(filename, hash_str);
		rc = 0;
	}

	return rc;
}

static bool match_ignore(const char* buffer)
{
	char* ignorestr = getenv("MALLOCFAIL_IGNORE");
	if (ignorestr == NULL) {
		return false;
	}
	char* copy = strdup(ignorestr);
	if (copy == NULL) {
		return false;
	}
	char* rest;
	char* token;
	bool status = false;
	for (token = strtok_r(copy, ";", &rest);
    	token != NULL;
    	token = strtok_r(NULL, ";", &rest))
	{
		if (strstr(buffer, token)) {
			status = true;
			break;
		}
	}
	free(copy);
	return status;
}

struct backtrace_context {
	XXH3_state_t* hash_context;
	bool ignore;
};

static int backtrace_callback(void *data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
	int len;
	struct backtrace_context* context = (struct backtrace_context*)data;

	if(lineno){
		len = snprintf(strbuf, 1024, "%s:%s:%d\n", filename, function, lineno);
		XXH3_64bits_update(context->hash_context, (const uint8_t*)strbuf, len);
		if (match_ignore(strbuf)) {
			context->ignore = true;
		}
	}

	return 0;
}


static bool create_backtrace_hash(char *hash_str, size_t hash_str_len)
{
	struct backtrace_context context;
	memset(&context, 0, sizeof(struct backtrace_context));
	context.hash_context = XXH3_createState();
	if (XXH3_64bits_reset(context.hash_context) == XXH_ERROR) abort();
	backtrace_full(state, 0, backtrace_callback, NULL, &context);
	XXH64_hash_t const hash = XXH3_64bits_digest(context.hash_context);
	//snprintf(hash_str, hash_str_len, "%lu", hash);
	hex_encode((const uint8_t*)&hash, sizeof(hash), hash_str);
	//hash_str[hash_str_len-1] = '\0';
	XXH3_freeState(context.hash_context);
	return context.ignore;

}


static int backtrace_print_callback(void *data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
	if(lineno && ++backtrace_count > -3){
		printf("%s:%s:%d\n", filename, function, lineno);
	}

	return 0;
}


static void print_backtrace(void)
{
	printf("------- Start trace -------\n");
	backtrace_count = 0;
	backtrace_full(state, 0, backtrace_print_callback, NULL, NULL);
	printf("------- End trace -------\n");
}


int should_malloc_fail(void)
{
	char hash_str[1024];
	int exists;

	if(max_fail_count == -1){
		char *env = getenv("MALLOCFAIL_FAIL_COUNT");
		if(env){
			max_fail_count = atoi(env);
			if(max_fail_count < 0){
				max_fail_count = 0;
			}
		}else{
			max_fail_count = 0;
		}
	}

	if(max_fail_count > 0 && fail_count >= max_fail_count){
		return 0;
	}

	if(!state){
		state = backtrace_create_state(NULL, 1, NULL, NULL);
	}

	if(!hashfile){
		hashfile = getenv("MALLOCFAIL_FILE");
		if(!hashfile){
			hashfile = hashfile_default;
		}
	}

	if(debug == -1){
		if(getenv("MALLOCFAIL_DEBUG")){
			debug = 1;
		}else{
			debug = 0;
		}
	}

	bool ignore = create_backtrace_hash(hash_str, sizeof(hash_str));
	exists = stack_context_exists(hashfile, hash_str);

	bool should_fail = !ignore && !exists;

	if(should_fail && debug){
		print_backtrace();
	}
	if(!should_fail){
		return 0;
	}else{
		fail_count++;
		return 1;
	}
}
