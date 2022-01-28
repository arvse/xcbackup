/* ------------------------------------------------------------------
 * SBox - Archive Unpack Task
 * ------------------------------------------------------------------ */

#include "xcbackup.h"

/**
 * Create new expandable buffer
 */
static int ext_buffer_new ( struct ext_buffer_t *buffer )
{
    buffer->length = 0;
    buffer->capacity = 256;

    if ( !( buffer->bytes = ( uint8_t * ) malloc ( buffer->capacity ) ) )
    {
        return -1;
    }

    return 0;
}

/**
 * Clear expandable buffer content
 */
static void ext_buffer_clear ( struct ext_buffer_t *buffer )
{
    buffer->length = 0;
}

/**
 * Append one byte to expandable buffer
 */
static int ext_buffer_append ( struct ext_buffer_t *buffer, uint8_t byte )
{
    uint8_t *backup;

    if ( buffer->length + 1 >= buffer->capacity )
    {
        buffer->capacity = 2 * ( buffer->length + 1 );
        backup = buffer->bytes;

        if ( !( buffer->bytes = realloc ( buffer->bytes, buffer->capacity ) ) )
        {
            free ( backup );
            return -1;
        }
    }

    buffer->bytes[buffer->length++] = byte;
    return 0;
}

/**
 * Free expandable buffer from memory
 */
static void ext_buffer_free ( struct ext_buffer_t *buffer )
{
    free ( buffer->bytes );
}

/**
 * SBox archive unpack callback
 */
int xcbackup_unpack_callback ( void *context )
{
    int fd = -1;
    uint8_t byte;
    uint32_t size;
    size_t len;
    size_t sum = 0;
    char* path;
    struct io_stream_t *io = NULL;
    struct iter_context_t *iter_context;
    uint8_t temp[ARCHIVE_PREFIX_LENGTH];
    uint8_t prefix[ARCHIVE_PREFIX_LENGTH] = { 0 };
    
    iter_context = ( struct iter_context_t * ) context;

    if (iter_context->file->read_complete(iter_context->file, prefix, sizeof(prefix)) < 0)
    {
        return -2;
    }

    for(len = 0; memcmp(prefix, xcbackup_archive_prefix,ARCHIVE_PREFIX_LENGTH) != 0; len++)
    {
        memcpy(temp, prefix + 1, ARCHIVE_PREFIX_LENGTH - 1);
        memcpy(prefix, temp, ARCHIVE_PREFIX_LENGTH - 1);
    
        if (iter_context->file->read_complete(iter_context->file, prefix + ARCHIVE_PREFIX_LENGTH - 1, 1) < 0)
        {
            return -1;
        }
        
        if (len && len % 65536)
        {
            fprintf(stderr, "Warning: Discarded 65k data block.\n");
        }
    }
    
    if (len)
    {
        fprintf(stderr, "Warning: Discarded bytes count: %lu.\n", (unsigned long) len);
    }

    if (input_aes_stream_split(iter_context->io, iter_context->password)  < 0)
    {
        return -1;
    }
    
    ext_buffer_clear ( &iter_context->extbuf );

    path = (char*) iter_context->extbuf.bytes;

    do
    {
        if ( iter_context->io->read_complete(iter_context->io, &byte, sizeof ( byte ) ) < 0 )
        {
            return -1;
        }

        if (byte == '/' && !(iter_context->options & OPTION_TESTONLY))
        {   
            if (strchr(path, '/') == path )
            {
                path++;
            }
            
            if (*path)
            {
            if ( ext_buffer_append ( &iter_context->extbuf, '\0' ) < 0 )
            {
                return -1;
            }
         
            if (access ( path, F_OK ) < 0 )
            {
                if (mkdir(path, 0755) < 0)
                {
                    fprintf(stderr, "Warning: Cannot create directory: '%s'.\n", path);
                }
            }
            
            iter_context->extbuf.length--;
            }
        }
        
        if ( ext_buffer_append ( &iter_context->extbuf, byte ) < 0 )
        {
            return -1;
        }

    } while ( byte );
    
    if (!*path || strstr(path, ".."))
    {
        fprintf(stderr, "Error: Path '%s' is restricted!\n", path);
        return -1;
    }
    
     if ( iter_context->io->read_complete(iter_context->io, &size, sizeof ( size ) ) < 0 )
        {
            return -1;
        }

        size = ntohl(size);
     
    if (!(iter_context->options & OPTION_TESTONLY))
    {
        if ( ( fd = open ( path, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, 0644 ) ) < 0 )
        {
            perror ( path );
            return -1;
        }

        if ( !( io = file_stream_new ( fd ) ) )
        {
            close ( fd );
            return -1;
        }
    }
    
    if ( size )
    {
        do
        {
            len = MIN ( sizeof ( iter_context->buffer ), size - sum );

            if ( iter_context->io->read_complete ( iter_context->io, iter_context->buffer,
                    len ) < 0 )
            {
                if (!(iter_context->options & OPTION_TESTONLY))
                {
                    close ( fd );
                }
                return -1;
            }

            if (!(iter_context->options & OPTION_TESTONLY))
            {
                if ( io->write_complete ( io, iter_context->buffer, len ) < 0 )
                {
                    perror ( path );
                    close ( fd );
                    return -1;
                }
            }
            
            sum += len;

        } while ( sum < size );
    }

    if (!(iter_context->options & OPTION_TESTONLY))
    {
        io->close ( io );
    }

    if ( iter_context->io->verify ( iter_context->io ) < 0 )
    {
        fprintf(stderr, "Warning: Invalid checkum at '%s'.\n", path);
    }

    if ( iter_context->options & OPTION_VERBOSE )
    {
        show_progress ( (iter_context->options & OPTION_TESTONLY) ? 't' : 'x', path );
    }

    return 0;
}

/** 
 * Unpack files from an archive
 */
int xcbackup_unpack_archive ( const char *archive, uint32_t options, const char *password )
{
    int fd;
    int status = 0;
    struct io_stream_t *io;
    struct io_stream_t *raw;
    struct io_stream_t *file;
    struct iter_context_t *iter_context;

    if ( ( fd = open ( archive, O_RDONLY | O_BINARY ) ) < 0 )
    {
        perror ( archive );
        return -1;
    }

   if ( !( raw = file_stream_new ( fd ) ) )
    {
        close ( fd );
        return -1;
    }
    
    if ( !( file = buffer_stream_new ( raw ) ) )
    {
        raw->close(raw);
        return -1;
    }
    
    if ( !( io = input_aes_stream_new ( file, password ) ) )
    {
        file->close(file);
        return -1;
    }

    if ( !( iter_context =
            ( struct iter_context_t * ) malloc ( sizeof ( struct iter_context_t ) ) ) )
    {
        io->close ( io );
        return -1;
    }

    iter_context->options = options;
    iter_context->io = io;
    iter_context->file = file;
    iter_context->password = password;

    if ( ext_buffer_new ( &iter_context->extbuf ) < 0 )
    {
        free ( iter_context );
        io->close ( io );
        return -1;
    }

    for (;;)
    {
        if ((status = xcbackup_unpack_callback(iter_context)) < 0)
        {
            if (status == -2)
            {
                status = 0;
                break;
            
            } else
            {
                fprintf(stderr, "Warning: Failed to unpack file.\n");
            }
        }
    }
    
    ext_buffer_free ( &iter_context->extbuf);
  
    free ( iter_context );
    io->close ( io );

    return status;
}
