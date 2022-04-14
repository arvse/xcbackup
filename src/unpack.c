/* ------------------------------------------------------------------
 * XCBackup - Archive Unpack Task
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
 * Remove unprintable characters from string
 */
static void remove_unprintable ( char *input )
{
    size_t i;
    size_t len;

    len = strlen ( input );

    for ( i = 0; i < len; i++ )
    {
        if ( !isprint ( input[i] ) )
        {
            input[i] = '?';
        }
    }
}

/**
 * XCBackup archive unpack callback
 */
int xcbackup_unpack_callback ( void *context )
{
    int fd = -1;
    int realunpack;
    int emptydir = 0;
    char taskcode = '\0';
    off_t backup;
    uint8_t byte;
    uint32_t size;
    uint32_t modified;
    size_t len;
    size_t sum = 0;
    char *path;
    struct io_stream_t *io = NULL;
    struct iter_context_t *iter_context;
    uint8_t temp[ARCHIVE_PREFIX_LENGTH];
    uint8_t prefix[ARCHIVE_PREFIX_LENGTH] = { 0 };
    struct stat statbuf;
    const char *tmppath = "tmpfile";

    iter_context = ( struct iter_context_t * ) context;

    realunpack = !( iter_context->options & ( OPTION_LISTONLY | OPTION_TESTONLY ) );

    if ( iter_context->file->read_complete ( iter_context->file, prefix, sizeof ( prefix ) ) < 0 )
    {
        return -2;
    }

    for ( len = 0; memcmp ( prefix, xcbackup_archive_prefix, ARCHIVE_PREFIX_LENGTH ) != 0; len++ )
    {
        memcpy ( temp, prefix + 1, ARCHIVE_PREFIX_LENGTH - 1 );
        memcpy ( prefix, temp, ARCHIVE_PREFIX_LENGTH - 1 );

        if ( iter_context->file->read_complete ( iter_context->file,
                prefix + ARCHIVE_PREFIX_LENGTH - 1, 1 ) < 0 )
        {
            return -1;
        }
    }

    if ( ( backup = lseek ( iter_context->fd, 0, SEEK_CUR ) ) < 0 )
    {
        perror ( "lseek" );
        return -1;
    }

    backup++;

    if ( len )
    {
        fprintf ( stderr, "Warning: Discarded bytes count: %lu.\n", ( unsigned long ) len );
    }

    if ( input_aes_stream_split ( iter_context->io, iter_context->password ) < 0 )
    {
        return -1;
    }

    ext_buffer_clear ( &iter_context->extbuf );

    path = ( char * ) iter_context->extbuf.bytes;

    do
    {
        if ( iter_context->io->read_complete ( iter_context->io, &byte, sizeof ( byte ) ) < 0 )
        {
            return -1;
        }

        if ( ext_buffer_append ( &iter_context->extbuf, byte ) < 0 )
        {
            return -1;
        }

    } while ( byte );

    if ( !*path || *path == '/' || strstr ( path, ".." ) )
    {
        remove_unprintable ( path );
        fprintf ( stderr, "Error: Path '%s' is restricted!\n", path );
        realunpack = 0;
    }

    if ( path[strlen ( path ) - 1] == '/' )
    {
        if ( iter_context->io->verify ( iter_context->io ) < 0 )
        {
            if ( !( iter_context->options & OPTION_LISTONLY ) )
            {
                fprintf ( stderr, "Warning: Invalid checksum at '%s'.\n", path );
                return -1;
            }

            if ( lseek ( iter_context->fd, backup, SEEK_SET ) < 0 )
            {
                return -1;
            }
        }

        emptydir = 1;
    }

    if ( realunpack )
    {
        path = ( char * ) iter_context->extbuf.bytes;

        while ( *path )
        {
            if ( *path == '/' )
            {
                *path = '\0';

                if ( access ( ( char * ) iter_context->extbuf.bytes, F_OK ) < 0 )
                {
                    if ( mkdir ( ( char * ) iter_context->extbuf.bytes, 0755 ) < 0 )
                    {
                        fprintf ( stderr, "Warning: Cannot create directory: '%s'.\n",
                            ( char * ) iter_context->extbuf.bytes );
                    }
                }

                *path = '/';
            }
            path++;
        }
    }

    path = ( char * ) iter_context->extbuf.bytes;

    if ( emptydir )
    {
        return 0;
    }

    if ( iter_context->io->read_complete ( iter_context->io, &size, sizeof ( size ) ) < 0 )
    {
        return -1;
    }

    size = ntohl ( size );

    if ( iter_context->io->read_complete ( iter_context->io, &modified, sizeof ( modified ) ) < 0 )
    {
        return -1;
    }

    modified = ntohl ( modified );

    if ( stat ( path, &statbuf ) >= 0 )
    {
        if ( statbuf.st_mtime > modified )
        {
            fprintf ( stderr, "Warning: Skipping file '%s' due to old timestamp.\n", path );
            taskcode = 'k';
            realunpack = 0;
        }
    }

    if ( realunpack )
    {
        if ( ( fd = open ( tmppath, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, 0644 ) ) < 0 )
        {
            perror ( tmppath );
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
                if ( realunpack )
                {
                    close ( fd );
                }

                return -1;
            }

            if ( realunpack )
            {
                if ( io->write_complete ( io, iter_context->buffer, len ) < 0 )
                {
                    perror ( tmppath );
                    close ( fd );
                    return -1;
                }
            }

            sum += len;

        } while ( sum < size );
    }

    if ( realunpack )
    {
        io->close ( io );
    }

    if ( iter_context->io->verify ( iter_context->io ) < 0 )
    {
        if ( lseek ( iter_context->fd, backup, SEEK_SET ) < 0 )
        {
            return -1;
        }

        fprintf ( stderr, "Warning: Invalid checksum at '%s'\n", path );

        if ( realunpack )
        {
            if ( !( iter_context->options & OPTION_LISTONLY ) )
            {
                return -1;
            }
        }
    }

    if ( realunpack )
    {
        if ( access ( path, F_OK ) >= 0 )
        {
            if ( unlink ( path ) < 0 )
            {
                perror ( path );
                return -1;
            }
        }

        if ( rename ( tmppath, path ) < 0 )
        {
            perror ( path );
            return -1;
        }
    }

    if ( iter_context->options & OPTION_VERBOSE )
    {
        if ( !taskcode )
        {
            if ( iter_context->options & OPTION_LISTONLY )
            {
                taskcode = 'l';

            } else if ( iter_context->options & OPTION_TESTONLY )
            {
                taskcode = 't';

            } else
            {
                taskcode = 'x';
            }
        }
        remove_unprintable ( path );
        show_progress ( taskcode, path );
    }

    return 0;
}

/** 
 * Unpack files from an archive
 */
int xcbackup_unpack_archive ( const char *archive, uint32_t options, const char *password,
    unsigned long offset )
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

    if ( options & OPTION_OFFSET )
    {
        printf ( "input file offset: %lu bytes\n", offset );

        if ( lseek ( fd, offset, SEEK_SET ) < 0 )
        {
            perror ( "lseek" );
            close ( fd );
            return -1;
        }
    }

    if ( !( raw = file_stream_new ( fd ) ) )
    {
        close ( fd );
        return -1;
    }

    if ( !( file = buffer_stream_new ( raw ) ) )
    {
        raw->close ( raw );
        return -1;
    }

    if ( !( io = input_aes_stream_new ( file, password ) ) )
    {
        file->close ( file );
        return -1;
    }

    if ( !( iter_context =
            ( struct iter_context_t * ) malloc ( sizeof ( struct iter_context_t ) ) ) )
    {
        io->close ( io );
        return -1;
    }

    iter_context->fd = fd;
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

    for ( ;; )
    {
        if ( ( status = xcbackup_unpack_callback ( iter_context ) ) < 0 )
        {
            if ( status == -2 )
            {
                status = 0;
                break;

            } else
            {
                fprintf ( stderr, "Warning: Failed to unpack file.\n" );
            }
        }
    }

    ext_buffer_free ( &iter_context->extbuf );

    free ( iter_context );
    io->close ( io );

    return status;
}
