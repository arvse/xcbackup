/* ------------------------------------------------------------------
 * XCBackup - Creation of New Streams
 * ------------------------------------------------------------------ */

#include "xcbackup.h"

/**
 * Create new IO stream
 */
struct io_stream_t *io_stream_new ( void )
{
    struct io_stream_t *io;

    if ( !( io = ( struct io_stream_t * ) calloc ( 1, sizeof ( struct io_stream_t ) ) ) )
    {
        return NULL;
    }

    io->read_complete = stream_read_complete;
    io->read_max = stream_read_max;
    io->write_complete = stream_write_complete;

    return io;
}

/**
 * Read complete data chunk from stream
 */
int stream_read_complete ( struct io_stream_t *io, void *mem, size_t total )
{
    size_t len;
    size_t sum;

    for ( sum = 0; sum < total; sum += len )
    {
        if ( ( ssize_t ) ( len = io->read ( io, ( uint8_t * ) mem + sum, total - sum ) ) < 0 )
        {
            return -1;
        }

        if ( !len )
        {
            errno = ENODATA;
            return -1;
        }
    }

    return 0;
}

/**
 * Read longest data chunk from stream
 */
ssize_t stream_read_max ( struct io_stream_t *io, void *mem, size_t total )
{
    size_t len;
    size_t sum;

    for ( sum = 0; sum < total; sum += len )
    {
        if ( ( ssize_t ) ( len = io->read ( io, ( uint8_t * ) mem + sum, total - sum ) ) < 0 )
        {
            return -1;
        }

        if ( !len )
        {
            break;
        }
    }

    return sum;
}

/**
 * Write complete data chunk to stream
 */
int stream_write_complete ( struct io_stream_t *io, const void *mem, size_t total )
{
    size_t len;
    size_t sum;

    for ( sum = 0; sum < total; sum += len )
    {
        if ( ( ssize_t ) ( len =
                io->write ( io, ( const uint8_t * ) mem + sum, total - sum ) ) <= 0 )
        {
            return -1;
        }
    }

    return 0;
}
