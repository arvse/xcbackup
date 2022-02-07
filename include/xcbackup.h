/* ------------------------------------------------------------------
 * SBox - Project Shared Header
 * ------------------------------------------------------------------ */

#include "config.h"

#ifndef XCBACKUP_H
#define XCBACKUP_H

#define XCBACKUP_VERSION "2.0.11"

#define ARCHIVE_PREFIX_LENGTH 16

#define OPTION_VERBOSE 1
#define OPTION_LISTONLY 2
#define OPTION_TESTONLY 4
#define OPTION_OFFSET 8

#define RANDOM_OFFSET ((unsigned long) -1)

/**
 * SBox Archive Node
 */
struct xcbackup_node_t
{
    uint32_t mode;
    time_t mtime;
    uint32_t size;
    char *name;
    struct xcbackup_node_t *head;
    struct xcbackup_node_t *tail;
    struct xcbackup_node_t *next;
    struct xcbackup_node_t *prev;
};

/**
 * Expandable buffer structure
 */
struct ext_buffer_t
{
    uint8_t *bytes;
    size_t length;
    size_t capacity;
};

/**
 * SBox iterate context
 */
struct iter_context_t
{
    int fd;
    int options;
    unsigned long size;
    struct io_stream_t *io;
    struct io_stream_t *file;
    const char *password;
    struct ext_buffer_t extbuf;
    char buffer[CHUNK_SIZE];
};

/**
 * IO Stream context
 */
struct io_stream_t
{
    void *context;
      ssize_t ( *read ) ( struct io_stream_t *, void *, size_t );
      ssize_t ( *write ) ( struct io_stream_t *, const void *, size_t );
    int ( *read_complete ) ( struct io_stream_t *, void *, size_t );
      ssize_t ( *read_max ) ( struct io_stream_t *, void *, size_t );
    int ( *write_complete ) ( struct io_stream_t *, const void *, size_t );
    int ( *verify ) ( struct io_stream_t * );
    int ( *flush ) ( struct io_stream_t * );
    void ( *close ) ( struct io_stream_t * );
};

/**
 * File net browsing callback
 */
typedef int ( *file_net_iter_callback ) ( void *, struct xcbackup_node_t *, const char * );

/**
 * Pack files to an archive
 */
extern int xcbackup_pack_archive ( const char *archive, uint32_t options, const char *password,
    unsigned long offset, const char *files[] );

/** 
 * Unpack files from an archive
 */
extern int xcbackup_unpack_archive ( const char *archive, uint32_t options, const char *password );

/**
 * Show operation progress with current file path
 */
extern void show_progress ( char action, const char *path );

/**
 * SBox archive prefix
 */
extern const uint8_t xcbackup_archive_prefix[ARCHIVE_PREFIX_LENGTH];

/**
 * SBox archive postfix
 */
extern const uint8_t xcbackup_archive_postfix[ARCHIVE_PREFIX_LENGTH];
/**
 * Create new IO stream
 */
extern struct io_stream_t *io_stream_new ( void );

/**
 * Read complete data chunk from stream
 */
extern int stream_read_complete ( struct io_stream_t *io, void *mem, size_t total );

/**
 * Read longest data chunk from stream
 */
extern ssize_t stream_read_max ( struct io_stream_t *io, void *mem, size_t total );

/**
 * Write complete data chunk to stream
 */
extern int stream_write_complete ( struct io_stream_t *io, const void *mem, size_t total );

/**
 * Create new file stream
 */
extern struct io_stream_t *file_stream_new ( int fd );

/**
 * Create new input AES stream
 */
#ifdef ENABLE_ENCRYPTION
extern struct io_stream_t *input_aes_stream_new ( struct io_stream_t *internal,
    const char *password );
#endif

/**
 * Create new output AES stream
 */
#ifdef ENABLE_ENCRYPTION
extern struct io_stream_t *output_aes_stream_new ( struct io_stream_t *internal,
    const char *password );
#endif

/**
 * Split input AES stream
 */
#ifdef ENABLE_ENCRYPTION
extern int input_aes_stream_split ( struct io_stream_t *io, const char *password );
#endif

/**
 * Split output AES stream
 */
#ifdef ENABLE_ENCRYPTION
extern int output_aes_stream_split ( struct io_stream_t *io );
#endif

/**
 * Create new output LZ4 stream
 */
#ifdef ENABLE_LZ4
extern struct io_stream_t *output_lz4_stream_new ( struct io_stream_t *internal, int level );
#endif

/**
 * Create new input LZ4 stream
 */
#ifdef ENABLE_LZ4
extern struct io_stream_t *input_lz4_stream_new ( struct io_stream_t *internal );
#endif

/**
 * Create new buffer stream
 */
extern struct io_stream_t *buffer_stream_new ( struct io_stream_t *internal );

/**
 * Create new file net from paths
 */
struct xcbackup_node_t *build_file_net ( const char *paths[] );

/**
 * Browse file net
 */
extern int file_net_iter ( struct xcbackup_node_t *root, void *context,
    file_net_iter_callback callback );

/**
 * Free file net from memory
 */
extern void free_file_net ( struct xcbackup_node_t *node );

/**
 * Save file net to stream
 */
extern int file_net_save ( struct xcbackup_node_t *root, struct io_stream_t *io );

/**
 * Load file net from stream
 */
extern struct xcbackup_node_t *file_net_load ( struct io_stream_t *io );


#endif
