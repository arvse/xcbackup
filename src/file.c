/* ------------------------------------------------------------------
 * SBox - File Stream Impl.
 * ------------------------------------------------------------------ */

#include "xcbackup.h"

/**
 * File stream context
 */
struct file_stream_context_t
{
    int fd;
};

/*
 * Read data from file stream
 */
static ssize_t file_stream_read ( struct io_stream_t *io, void *data, size_t len )
{
    struct file_stream_context_t *context;

    context = ( struct file_stream_context_t * ) io->context;

    return read ( context->fd, data, len );
}

/*
 * Write data to file stream
 */
static ssize_t file_stream_write ( struct io_stream_t *io, const void *data, size_t len )
{
    struct file_stream_context_t *context;

    context = ( struct file_stream_context_t * ) io->context;

    return write ( context->fd, data, len );
}

/*
 * Verify file stream integrity
 */
static int file_stream_verify ( struct io_stream_t *io )
{
    UNUSED ( io );
    return 0;
}

/*
 * Flush file stream output to file
 */
static int file_stream_flush ( struct io_stream_t *io )
{
#ifdef _GNU_SOURCE
    struct file_stream_context_t *context;

    context = ( struct file_stream_context_t * ) io->context;

    return syncfs ( context->fd );
#else
    UNUSED ( io );

    return 0;
#endif
}

/*
 * Close IO stream
 */
static void file_stream_close ( struct io_stream_t *io )
{
    struct file_stream_context_t *context;

    context = ( struct file_stream_context_t * ) io->context;

    if ( context->fd >= 0 )
    {
        close ( context->fd );
        context->fd = -1;
    }
    free ( io );
}

/**
 * Create new file stream
 */
struct io_stream_t *file_stream_new ( int fd )
{
    struct io_stream_t *io;
    struct file_stream_context_t *context;

    if ( !( io = io_stream_new (  ) ) )
    {
        return NULL;
    }

    if ( !( context =
            ( struct file_stream_context_t * ) malloc ( sizeof ( struct
                    file_stream_context_t ) ) ) )
    {
        free ( io );
        return NULL;
    }

    context->fd = fd;

    io->context = context;
    io->read = file_stream_read;
    io->write = file_stream_write;
    io->verify = file_stream_verify;
    io->flush = file_stream_flush;
    io->close = file_stream_close;

    return io;
}
